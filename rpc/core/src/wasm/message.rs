#![allow(non_snake_case)]
use crate::error::RpcError as Error;
use crate::error::RpcResult as Result;
use crate::model::*;
use cryptix_addresses::Address;
use cryptix_addresses::AddressOrStringArrayT;
use cryptix_consensus_client::Transaction;
use cryptix_consensus_client::UtxoEntryReference;
use cryptix_consensus_core::tx as cctx;
use cryptix_rpc_macros::declare_typescript_wasm_interface as declare;
pub use serde_wasm_bindgen::from_value;
use wasm_bindgen::prelude::*;
use workflow_wasm::convert::*;
use workflow_wasm::extensions::*;
use workflow_wasm::serde::to_value;

macro_rules! try_from {
    ($name:ident : $from_type:ty, $to_type:ty, $body:block) => {
        impl TryFrom<$from_type> for $to_type {
            type Error = Error;
            fn try_from($name: $from_type) -> Result<Self> {
                $body
            }
        }
    };
}

// ---

// Cryptix Atomic Token + Snapshot bootstrap interfaces

declare! {
    IRpcTokenContext,
    r#"
    /**
     * @category Node RPC
     */
    export interface IRpcTokenContext {
        atBlockHash : HexString;
        atDaaScore : bigint;
        stateHash : string;
        isDegraded : boolean;
    }
    "#,
}

try_from! ( args: RpcTokenContext, IRpcTokenContext, {
    Ok(to_value(&args)?.into())
});

declare! {
    IRpcTokenAsset,
    r#"
    /**
     * @category Node RPC
     */
    export interface IRpcTokenAsset {
        assetId : string;
        creatorOwnerId : string;
        tokenVersion : number;
        mintAuthorityOwnerId : string;
        decimals : number;
        supplyMode : number;
        maxSupply : string;
        totalSupply : string;
        name : string;
        symbol : string;
        metadataHex : string;
        createdBlockHash? : HexString;
        createdDaaScore? : bigint;
        createdAt? : bigint;
        platformTag : string;
    }
    "#,
}

try_from! ( args: RpcTokenAsset, IRpcTokenAsset, {
    Ok(to_value(&args)?.into())
});

declare! {
    IRpcTokenEvent,
    r#"
    /**
     * @category Node RPC
     */
    export interface IRpcTokenEvent {
        eventId : string;
        sequence : bigint;
        acceptingBlockHash : HexString;
        txid : HexString;
        eventType : number;
        applyStatus : number;
        noopReason : number;
        ordinal : number;
        reorgOfEventId? : string;
        opType? : number;
        assetId? : string;
        fromOwnerId? : string;
        toOwnerId? : string;
        amount? : string;
    }
    "#,
}

try_from! ( args: RpcTokenEvent, IRpcTokenEvent, {
    Ok(to_value(&args)?.into())
});

declare! {
    IRpcTokenOwnerBalance,
    r#"
    /**
     * @category Node RPC
     */
    export interface IRpcTokenOwnerBalance {
        assetId : string;
        balance : string;
        asset? : IRpcTokenAsset;
    }
    "#,
}

try_from! ( args: RpcTokenOwnerBalance, IRpcTokenOwnerBalance, {
    Ok(to_value(&args)?.into())
});

declare! {
    IRpcTokenHolder,
    r#"
    /**
     * @category Node RPC
     */
    export interface IRpcTokenHolder {
        ownerId : string;
        balance : string;
    }
    "#,
}

try_from! ( args: RpcTokenHolder, IRpcTokenHolder, {
    Ok(to_value(&args)?.into())
});

declare! {
    IRpcLiquidityFeeRecipient,
    r#"
    /**
     * @category Node RPC
     */
    export interface IRpcLiquidityFeeRecipient {
        ownerId : string;
        address : string;
        unclaimedSompi : string;
    }
    "#,
}

try_from! ( args: RpcLiquidityFeeRecipient, IRpcLiquidityFeeRecipient, {
    Ok(to_value(&args)?.into())
});

declare! {
    IRpcLiquidityPoolState,
    r#"
    /**
     * @category Node RPC
     */
    export interface IRpcLiquidityPoolState {
        assetId : string;
        poolNonce : bigint;
        curveVersion : number;
        feeBps : number;
        maxSupply : string;
        totalSupply : string;
        circulatingTokenSupply : string;
        realCpayReservesSompi : string;
        realTokenReserves : string;
        virtualCpayReservesSompi : string;
        virtualTokenReserves : string;
        maxBuyInSompi : string;
        maxTokensOut : string;
        unclaimedFeeTotalSompi : string;
        vaultValueSompi : string;
        vaultTxid : HexString;
        vaultOutputIndex : number;
        feeRecipients : IRpcLiquidityFeeRecipient[];
        liquidityLockEnabled : boolean;
        unlockTargetSompi : string;
        unlocked : boolean;
        sellLocked : boolean;
        liquidityCpaySompi : string;
        currentSpotPriceSompi : string;
        circulatingMcapCpaySompi : string;
        fdvMcapCpaySompi : string;
    }
    "#,
}

try_from! ( args: RpcLiquidityPoolState, IRpcLiquidityPoolState, {
    Ok(to_value(&args)?.into())
});

declare! {
    IRpcLiquidityHolder,
    r#"
    /**
     * @category Node RPC
     */
    export interface IRpcLiquidityHolder {
        address? : string;
        ownerId : string;
        balance : string;
    }
    "#,
}

try_from! ( args: RpcLiquidityHolder, IRpcLiquidityHolder, {
    Ok(to_value(&args)?.into())
});

declare! {
    IRpcScBootstrapSource,
    r#"
    /**
     * @category Node RPC
     */
    export interface IRpcScBootstrapSource {
        snapshotId : string;
        protocolVersion : number;
        networkId : string;
        nodeIdentity : string;
        atBlockHash : HexString;
        atDaaScore : bigint;
        stateHashAtFp : string;
        windowStartBlockHash : HexString;
        windowEndBlockHash : HexString;
    }
    "#,
}

try_from! ( args: RpcScBootstrapSource, IRpcScBootstrapSource, {
    Ok(to_value(&args)?.into())
});

declare! {
    IRpcScManifestSignature,
    r#"
    /**
     * @category Node RPC
     */
    export interface IRpcScManifestSignature {
        signerPubkeyHex : string;
        signatureHex : string;
    }
    "#,
}

try_from! ( args: RpcScManifestSignature, IRpcScManifestSignature, {
    Ok(to_value(&args)?.into())
});

declare! {
    ISimulateTokenOpRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface ISimulateTokenOpRequest {
        payloadHex : string;
        ownerId : string;
        atBlockHash? : HexString;
    }
    "#,
}

try_from! ( args: ISimulateTokenOpRequest, SimulateTokenOpRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    ISimulateTokenOpResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface ISimulateTokenOpResponse {
        result : string;
        noopReason? : number;
        expectedNextNonce : bigint;
        context : IRpcTokenContext;
    }
    "#,
}

try_from! ( args: SimulateTokenOpResponse, ISimulateTokenOpResponse, {
    Ok(to_value(&args)?.into())
});

declare! {
    IGetTokenBalanceRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetTokenBalanceRequest {
        assetId : string;
        ownerId : string;
        atBlockHash? : HexString;
    }
    "#,
}

try_from! ( args: IGetTokenBalanceRequest, GetTokenBalanceRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetTokenBalanceResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetTokenBalanceResponse {
        balance : string;
        context : IRpcTokenContext;
    }
    "#,
}

try_from! ( args: GetTokenBalanceResponse, IGetTokenBalanceResponse, {
    Ok(to_value(&args)?.into())
});

declare! {
    IGetTokenNonceRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetTokenNonceRequest {
        ownerId : string;
        atBlockHash? : HexString;
    }
    "#,
}

try_from! ( args: IGetTokenNonceRequest, GetTokenNonceRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetTokenNonceResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetTokenNonceResponse {
        expectedNextNonce : bigint;
        context : IRpcTokenContext;
    }
    "#,
}

try_from! ( args: GetTokenNonceResponse, IGetTokenNonceResponse, {
    Ok(to_value(&args)?.into())
});

declare! {
    IGetTokenAssetRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetTokenAssetRequest {
        assetId : string;
        atBlockHash? : HexString;
    }
    "#,
}

try_from! ( args: IGetTokenAssetRequest, GetTokenAssetRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetTokenAssetResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetTokenAssetResponse {
        asset? : IRpcTokenAsset;
        context : IRpcTokenContext;
    }
    "#,
}

try_from! ( args: GetTokenAssetResponse, IGetTokenAssetResponse, {
    Ok(to_value(&args)?.into())
});

declare! {
    IGetTokenOpStatusRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetTokenOpStatusRequest {
        txid : HexString;
        atBlockHash? : HexString;
    }
    "#,
}

try_from! ( args: IGetTokenOpStatusRequest, GetTokenOpStatusRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetTokenOpStatusResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetTokenOpStatusResponse {
        acceptingBlockHash? : HexString;
        applyStatus? : number;
        noopReason? : number;
        context : IRpcTokenContext;
    }
    "#,
}

try_from! ( args: GetTokenOpStatusResponse, IGetTokenOpStatusResponse, {
    Ok(to_value(&args)?.into())
});

declare! {
    IGetTokenStateHashRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetTokenStateHashRequest {
        atBlockHash? : HexString;
    }
    "#,
}

try_from! ( args: IGetTokenStateHashRequest, GetTokenStateHashRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetTokenStateHashResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetTokenStateHashResponse {
        context : IRpcTokenContext;
    }
    "#,
}

try_from! ( args: GetTokenStateHashResponse, IGetTokenStateHashResponse, {
    Ok(to_value(&args)?.into())
});

declare! {
    IGetTokenSpendabilityRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetTokenSpendabilityRequest {
        assetId : string;
        ownerId : string;
        minDaaForSpend? : bigint;
        atBlockHash? : HexString;
    }
    "#,
}

try_from! ( args: IGetTokenSpendabilityRequest, GetTokenSpendabilityRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetTokenSpendabilityResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetTokenSpendabilityResponse {
        canSpend : boolean;
        reason? : string;
        balance : string;
        expectedNextNonce : bigint;
        minDaaForSpend : bigint;
        context : IRpcTokenContext;
    }
    "#,
}

try_from! ( args: GetTokenSpendabilityResponse, IGetTokenSpendabilityResponse, {
    Ok(to_value(&args)?.into())
});

declare! {
    IGetTokenEventsRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetTokenEventsRequest {
        afterSequence : bigint;
        limit : number;
        atBlockHash? : HexString;
    }
    "#,
}

try_from! ( args: IGetTokenEventsRequest, GetTokenEventsRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetTokenEventsResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetTokenEventsResponse {
        events : IRpcTokenEvent[];
        context : IRpcTokenContext;
    }
    "#,
}

try_from! ( args: GetTokenEventsResponse, IGetTokenEventsResponse, {
    Ok(to_value(&args)?.into())
});

declare! {
    IGetTokenAssetsRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetTokenAssetsRequest {
        offset : number;
        limit : number;
        query? : string;
        atBlockHash? : HexString;
    }
    "#,
}

try_from! ( args: IGetTokenAssetsRequest, GetTokenAssetsRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetTokenAssetsResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetTokenAssetsResponse {
        assets : IRpcTokenAsset[];
        total : bigint;
        context : IRpcTokenContext;
    }
    "#,
}

try_from! ( args: GetTokenAssetsResponse, IGetTokenAssetsResponse, {
    Ok(to_value(&args)?.into())
});

declare! {
    IGetTokenBalancesByOwnerRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetTokenBalancesByOwnerRequest {
        ownerId : string;
        offset : number;
        limit : number;
        includeAssets : boolean;
        atBlockHash? : HexString;
    }
    "#,
}

try_from! ( args: IGetTokenBalancesByOwnerRequest, GetTokenBalancesByOwnerRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetTokenBalancesByOwnerResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetTokenBalancesByOwnerResponse {
        balances : IRpcTokenOwnerBalance[];
        total : bigint;
        context : IRpcTokenContext;
    }
    "#,
}

try_from! ( args: GetTokenBalancesByOwnerResponse, IGetTokenBalancesByOwnerResponse, {
    Ok(to_value(&args)?.into())
});

declare! {
    IGetTokenHoldersRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetTokenHoldersRequest {
        assetId : string;
        offset : number;
        limit : number;
        atBlockHash? : HexString;
    }
    "#,
}

try_from! ( args: IGetTokenHoldersRequest, GetTokenHoldersRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetTokenHoldersResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetTokenHoldersResponse {
        holders : IRpcTokenHolder[];
        total : bigint;
        context : IRpcTokenContext;
    }
    "#,
}

try_from! ( args: GetTokenHoldersResponse, IGetTokenHoldersResponse, {
    Ok(to_value(&args)?.into())
});

declare! {
    IGetTokenOwnerIdByAddressRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetTokenOwnerIdByAddressRequest {
        address : string;
        atBlockHash? : HexString;
    }
    "#,
}

try_from! ( args: IGetTokenOwnerIdByAddressRequest, GetTokenOwnerIdByAddressRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetTokenOwnerIdByAddressResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetTokenOwnerIdByAddressResponse {
        ownerId? : string;
        reason? : string;
        context : IRpcTokenContext;
    }
    "#,
}

try_from! ( args: GetTokenOwnerIdByAddressResponse, IGetTokenOwnerIdByAddressResponse, {
    Ok(to_value(&args)?.into())
});

declare! {
    IGetLiquidityPoolStateRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetLiquidityPoolStateRequest {
        assetId : string;
        atBlockHash? : HexString;
    }
    "#,
}

try_from! ( args: IGetLiquidityPoolStateRequest, GetLiquidityPoolStateRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetLiquidityPoolStateResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetLiquidityPoolStateResponse {
        pool? : IRpcLiquidityPoolState;
        context : IRpcTokenContext;
    }
    "#,
}

try_from! ( args: GetLiquidityPoolStateResponse, IGetLiquidityPoolStateResponse, {
    Ok(to_value(&args)?.into())
});

declare! {
    IGetLiquidityQuoteRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetLiquidityQuoteRequest {
        assetId : string;
        side : number;
        exactInAmount : string;
        atBlockHash? : HexString;
    }
    "#,
}

try_from! ( args: IGetLiquidityQuoteRequest, GetLiquidityQuoteRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetLiquidityQuoteResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetLiquidityQuoteResponse {
        side : number;
        exactInAmount : string;
        feeAmountSompi : string;
        netInAmount : string;
        amountOut : string;
        context : IRpcTokenContext;
    }
    "#,
}

try_from! ( args: GetLiquidityQuoteResponse, IGetLiquidityQuoteResponse, {
    Ok(to_value(&args)?.into())
});

declare! {
    IGetLiquidityFeeStateRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetLiquidityFeeStateRequest {
        assetId : string;
        atBlockHash? : HexString;
    }
    "#,
}

try_from! ( args: IGetLiquidityFeeStateRequest, GetLiquidityFeeStateRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetLiquidityFeeStateResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetLiquidityFeeStateResponse {
        assetId : string;
        feeBps : number;
        totalUnclaimedSompi : string;
        recipients : IRpcLiquidityFeeRecipient[];
        context : IRpcTokenContext;
    }
    "#,
}

try_from! ( args: GetLiquidityFeeStateResponse, IGetLiquidityFeeStateResponse, {
    Ok(to_value(&args)?.into())
});

declare! {
    IGetLiquidityClaimPreviewRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetLiquidityClaimPreviewRequest {
        assetId : string;
        recipientAddress : string;
        atBlockHash? : HexString;
    }
    "#,
}

try_from! ( args: IGetLiquidityClaimPreviewRequest, GetLiquidityClaimPreviewRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetLiquidityClaimPreviewResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetLiquidityClaimPreviewResponse {
        recipientAddress : string;
        ownerId? : string;
        claimableAmountSompi : string;
        minPayoutSompi : string;
        claimableNow : boolean;
        reason? : string;
        context : IRpcTokenContext;
    }
    "#,
}

try_from! ( args: GetLiquidityClaimPreviewResponse, IGetLiquidityClaimPreviewResponse, {
    Ok(to_value(&args)?.into())
});

declare! {
    IGetLiquidityHoldersRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetLiquidityHoldersRequest {
        assetId : string;
        offset : number;
        limit : number;
        atBlockHash? : HexString;
    }
    "#,
}

try_from! ( args: IGetLiquidityHoldersRequest, GetLiquidityHoldersRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetLiquidityHoldersResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetLiquidityHoldersResponse {
        holders : IRpcLiquidityHolder[];
        total : bigint;
        context : IRpcTokenContext;
    }
    "#,
}

try_from! ( args: GetLiquidityHoldersResponse, IGetLiquidityHoldersResponse, {
    Ok(to_value(&args)?.into())
});

declare! {
    IGetConsensusAtomicStateHashRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetConsensusAtomicStateHashRequest {
        blockHash : HexString;
    }
    "#,
}

try_from! ( args: IGetConsensusAtomicStateHashRequest, GetConsensusAtomicStateHashRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetConsensusAtomicStateHashResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetConsensusAtomicStateHashResponse {
        stateHash? : string;
    }
    "#,
}

try_from! ( args: GetConsensusAtomicStateHashResponse, IGetConsensusAtomicStateHashResponse, {
    Ok(to_value(&args)?.into())
});

declare! {
    IExportTokenSnapshotRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IExportTokenSnapshotRequest {
        path : string;
    }
    "#,
}

try_from! ( args: IExportTokenSnapshotRequest, ExportTokenSnapshotRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IExportTokenSnapshotResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IExportTokenSnapshotResponse {
        exported : boolean;
        context : IRpcTokenContext;
    }
    "#,
}

try_from! ( args: ExportTokenSnapshotResponse, IExportTokenSnapshotResponse, {
    Ok(to_value(&args)?.into())
});

declare! {
    IImportTokenSnapshotRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IImportTokenSnapshotRequest {
        path : string;
    }
    "#,
}

try_from! ( args: IImportTokenSnapshotRequest, ImportTokenSnapshotRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IImportTokenSnapshotResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IImportTokenSnapshotResponse {
        imported : boolean;
        context : IRpcTokenContext;
    }
    "#,
}

try_from! ( args: ImportTokenSnapshotResponse, IImportTokenSnapshotResponse, {
    Ok(to_value(&args)?.into())
});

declare! {
    IGetTokenHealthRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetTokenHealthRequest {
        atBlockHash? : HexString;
    }
    "#,
}

try_from! ( args: IGetTokenHealthRequest, GetTokenHealthRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetTokenHealthResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetTokenHealthResponse {
        isDegraded : boolean;
        bootstrapInProgress : boolean;
        liveCorrect : boolean;
        tokenState : string;
        lastAppliedBlock? : HexString;
        lastSequence : bigint;
        stateHash : string;
        context : IRpcTokenContext;
    }
    "#,
}

try_from! ( args: GetTokenHealthResponse, IGetTokenHealthResponse, {
    Ok(to_value(&args)?.into())
});

declare! {
    IGetScBootstrapSourcesRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetScBootstrapSourcesRequest { }
    "#,
}

try_from! ( args: IGetScBootstrapSourcesRequest, GetScBootstrapSourcesRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetScBootstrapSourcesResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetScBootstrapSourcesResponse {
        sources : IRpcScBootstrapSource[];
        context : IRpcTokenContext;
    }
    "#,
}

try_from! ( args: GetScBootstrapSourcesResponse, IGetScBootstrapSourcesResponse, {
    Ok(to_value(&args)?.into())
});

declare! {
    IGetScSnapshotManifestRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetScSnapshotManifestRequest {
        snapshotId : string;
    }
    "#,
}

try_from! ( args: IGetScSnapshotManifestRequest, GetScSnapshotManifestRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetScSnapshotManifestResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetScSnapshotManifestResponse {
        snapshotId : string;
        manifestHex : string;
        manifestSignatures : IRpcScManifestSignature[];
    }
    "#,
}

try_from! ( args: GetScSnapshotManifestResponse, IGetScSnapshotManifestResponse, {
    Ok(to_value(&args)?.into())
});

declare! {
    IGetScSnapshotChunkRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetScSnapshotChunkRequest {
        snapshotId : string;
        chunkIndex : number;
        chunkSize? : number;
    }
    "#,
}

try_from! ( args: IGetScSnapshotChunkRequest, GetScSnapshotChunkRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetScSnapshotChunkResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetScSnapshotChunkResponse {
        snapshotId : string;
        chunkIndex : number;
        totalChunks : number;
        fileSize : bigint;
        chunkHex : string;
    }
    "#,
}

try_from! ( args: GetScSnapshotChunkResponse, IGetScSnapshotChunkResponse, {
    Ok(to_value(&args)?.into())
});

declare! {
    IGetScReplayWindowChunkRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetScReplayWindowChunkRequest {
        snapshotId : string;
        chunkIndex : number;
        chunkSize? : number;
    }
    "#,
}

try_from! ( args: IGetScReplayWindowChunkRequest, GetScReplayWindowChunkRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetScReplayWindowChunkResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetScReplayWindowChunkResponse {
        snapshotId : string;
        chunkIndex : number;
        totalChunks : number;
        fileSize : bigint;
        chunkHex : string;
    }
    "#,
}

try_from! ( args: GetScReplayWindowChunkResponse, IGetScReplayWindowChunkResponse, {
    Ok(to_value(&args)?.into())
});

declare! {
    IGetScSnapshotHeadRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetScSnapshotHeadRequest { }
    "#,
}

try_from! ( args: IGetScSnapshotHeadRequest, GetScSnapshotHeadRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetScSnapshotHeadResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetScSnapshotHeadResponse {
        head? : IRpcScBootstrapSource;
        context : IRpcTokenContext;
    }
    "#,
}

try_from! ( args: GetScSnapshotHeadResponse, IGetScSnapshotHeadResponse, {
    Ok(to_value(&args)?.into())
});

// ---

#[wasm_bindgen(typescript_custom_section)]
const TS_ACCEPTED_TRANSACTION_IDS: &'static str = r#"
    /**
     * Accepted transaction IDs.
     * 
     * @category Node RPC
     */
    export interface IAcceptedTransactionIds {
        acceptingBlockHash : HexString;
        acceptedTransactionIds : HexString[];
    }
"#;

// ---

declare! {
    IPingRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IPingRequest {
        message?: string;
    }
    "#,
}

try_from! ( args: IPingRequest, PingRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IPingResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IPingResponse {
        message?: string;
    }
    "#,
}

try_from! ( args: PingResponse, IPingResponse, {
    Ok(to_value(&args)?.into())
});

declare! {
    IGetBlockCountRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetBlockCountRequest { }
    "#,
}

try_from! ( args: IGetBlockCountRequest, GetBlockCountRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetBlockCountResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetBlockCountResponse {
        headerCount : bigint;
        blockCount : bigint;
    }
    "#,
}

try_from! ( args: GetBlockCountResponse, IGetBlockCountResponse, {
    Ok(to_value(&args)?.into())
});

// ---

declare! {
    IGetBlockDagInfoRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetBlockDagInfoRequest { }
    "#,
}

try_from! ( args: IGetBlockDagInfoRequest, GetBlockDagInfoRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetBlockDagInfoResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetBlockDagInfoResponse {
        network: string;
        blockCount: bigint;
        headerCount: bigint;
        tipHashes: HexString[];
        difficulty: number;
        pastMedianTime: bigint;
        virtualParentHashes: HexString[];
        pruningPointHash: HexString;
        virtualDaaScore: bigint;
        sink: HexString;
    }
    "#,
}

try_from! ( args: GetBlockDagInfoResponse, IGetBlockDagInfoResponse, {
    Ok(to_value(&args)?.into())
});

// ---

declare! {
    IGetCoinSupplyRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetCoinSupplyRequest { }
    "#,
}

try_from! ( args: IGetCoinSupplyRequest, GetCoinSupplyRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetCoinSupplyResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetCoinSupplyResponse {
        maxSompi: bigint;
        circulatingSompi: bigint;
    }
    "#,
}

try_from! ( args: GetCoinSupplyResponse, IGetCoinSupplyResponse, {
    Ok(to_value(&args)?.into())
});

// ---

declare! {
    IGetConnectedPeerInfoRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetConnectedPeerInfoRequest { }
    "#,
}

try_from! ( args: IGetConnectedPeerInfoRequest, GetConnectedPeerInfoRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetConnectedPeerInfoResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetConnectedPeerInfoResponse {
        [key: string]: any
    }
    "#,
}

try_from! ( args: GetConnectedPeerInfoResponse, IGetConnectedPeerInfoResponse, {
    Ok(to_value(&args)?.into())
});

// ---

declare! {
    IGetInfoRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetInfoRequest { }
    "#,
}

try_from! ( args: IGetInfoRequest, GetInfoRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetInfoResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetInfoResponse {
        p2pId : string;
        mempoolSize : bigint;
        serverVersion : string;
        isUtxoIndexed : boolean;
        isSynced : boolean;
        /** GRPC ONLY */
        hasNotifyCommand : boolean;
        /** GRPC ONLY */
        hasMessageId : boolean;
    }
    "#,
}

try_from! ( args: GetInfoResponse, IGetInfoResponse, {
    Ok(to_value(&args)?.into())
});

// ---

declare! {
    IGetPeerAddressesRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetPeerAddressesRequest { }
    "#,
}

try_from! ( args: IGetPeerAddressesRequest, GetPeerAddressesRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetPeerAddressesResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetPeerAddressesResponse {
        [key: string]: any
    }
    "#,
}

try_from! ( args: GetPeerAddressesResponse, IGetPeerAddressesResponse, {
    Ok(to_value(&args)?.into())
});

// ---

declare! {
    IGetMetricsRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetMetricsRequest { }
    "#,
}

try_from! ( args: IGetMetricsRequest, GetMetricsRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetMetricsResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetMetricsResponse {
        [key: string]: any
    }
    "#,
}

try_from! ( args: GetMetricsResponse, IGetMetricsResponse, {
    Ok(to_value(&args)?.into())
});

// ---

declare! {
    IGetConnectionsRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetConnectionsRequest { }
    "#,
}

try_from! ( args: IGetConnectionsRequest, GetConnectionsRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetConnectionsResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetConnectionsResponse {
        [key: string]: any
    }
    "#,
}

try_from! ( args: GetConnectionsResponse, IGetConnectionsResponse, {
    Ok(to_value(&args)?.into())
});

// ---

declare! {
    IGetSinkRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetSinkRequest { }
    "#,
}

try_from! ( args: IGetSinkRequest, GetSinkRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetSinkResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetSinkResponse {
        sink : HexString;
    }
    "#,
}

try_from! ( args: GetSinkResponse, IGetSinkResponse, {
    Ok(to_value(&args)?.into())
});

// ---

declare! {
    IGetSinkBlueScoreRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetSinkBlueScoreRequest { }
    "#,
}

try_from! ( args: IGetSinkBlueScoreRequest, GetSinkBlueScoreRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetSinkBlueScoreResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetSinkBlueScoreResponse {
        blueScore : bigint;
    }
    "#,
}

try_from! ( args: GetSinkBlueScoreResponse, IGetSinkBlueScoreResponse, {
    Ok(to_value(&args)?.into())
});

// ---

declare! {
    IShutdownRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IShutdownRequest { }
    "#,
}

try_from! ( args: IShutdownRequest, ShutdownRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IShutdownResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IShutdownResponse { }
    "#,
}

try_from! ( args: ShutdownResponse, IShutdownResponse, {
    Ok(to_value(&args)?.into())
});

// ---

declare! {
    IGetServerInfoRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetServerInfoRequest { }
    "#,
}

try_from! ( args: IGetServerInfoRequest, GetServerInfoRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetServerInfoResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetServerInfoResponse {
        rpcApiVersion : number[];
        serverVersion : string;
        networkId : string;
        hasUtxoIndex : boolean;
        isSynced : boolean;
        virtualDaaScore : bigint;
    }
    "#,
}

try_from! ( args: GetServerInfoResponse, IGetServerInfoResponse, {
    Ok(to_value(&args)?.into())
});

// ---

declare! {
    IGetSyncStatusRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetSyncStatusRequest { }
    "#,
}

try_from! ( args: IGetSyncStatusRequest, GetSyncStatusRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetSyncStatusResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetSyncStatusResponse {
        isSynced : boolean;
    }
    "#,
}

try_from! ( args: GetSyncStatusResponse, IGetSyncStatusResponse, {
    Ok(to_value(&args)?.into())
});

/*
    Interfaces for methods with arguments
*/

declare! {
    IAddPeerRequest,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IAddPeerRequest {
        peerAddress : INetworkAddress;
        isPermanent : boolean;
    }
    "#,
}

try_from! ( args: IAddPeerRequest, AddPeerRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IAddPeerResponse,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IAddPeerResponse { }
    "#,
}

try_from! ( args: AddPeerResponse, IAddPeerResponse, {
    Ok(to_value(&args)?.into())
});

// ---
declare! {
    IBanRequest,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IBanRequest {
        /**
         * IPv4 or IPv6 address to ban.
         */
        ip : string;
    }
    "#,
}

try_from! ( args: IBanRequest, BanRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IBanResponse,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IBanResponse { }
    "#,
}

try_from! ( args: BanResponse, IBanResponse, {
    Ok(to_value(&args)?.into())
});

// ---

declare! {
    IEstimateNetworkHashesPerSecondRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IEstimateNetworkHashesPerSecondRequest {
        windowSize : number;
        startHash? : HexString;
    }
    "#,
}

try_from! ( args: IEstimateNetworkHashesPerSecondRequest, EstimateNetworkHashesPerSecondRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IEstimateNetworkHashesPerSecondResponse,
    r#"
    /**
     * @category Node RPC
     */
    export interface IEstimateNetworkHashesPerSecondResponse {
        networkHashesPerSecond : bigint;
    }
    "#,
}

try_from! ( args: EstimateNetworkHashesPerSecondResponse, IEstimateNetworkHashesPerSecondResponse, {
    Ok(to_value(&args)?.into())
});

// ---

declare! {
    IGetBalanceByAddressRequest,
    r#"
    /**
     * @category Node RPC
     */
    export interface IGetBalanceByAddressRequest {
        address : Address | string;
    }
    "#,
}

try_from! ( args: IGetBalanceByAddressRequest, GetBalanceByAddressRequest, {
    let js_value = JsValue::from(args);
    let request = if let Ok(address) = Address::try_owned_from(js_value.clone()) {
        GetBalanceByAddressRequest { address }
    } else {
        // TODO - evaluate Object property
        from_value::<GetBalanceByAddressRequest>(js_value)?
    };
    Ok(request)
});

declare! {
    IGetBalanceByAddressResponse,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IGetBalanceByAddressResponse {
        balance : bigint;
    }
    "#,
}

try_from! ( args: GetBalanceByAddressResponse, IGetBalanceByAddressResponse, {
    Ok(to_value(&args)?.into())
});

// ---

declare! {
    IGetBalancesByAddressesRequest,
    "IGetBalancesByAddressesRequest | Address[] | string[]",
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IGetBalancesByAddressesRequest {
        addresses : Address[] | string[];
    }
    "#,
}

try_from! ( args: IGetBalancesByAddressesRequest, GetBalancesByAddressesRequest, {
    let js_value = JsValue::from(args);
    let request = if let Ok(addresses) = Vec::<Address>::try_from(AddressOrStringArrayT::from(js_value.clone())) {
        GetBalancesByAddressesRequest { addresses }
    } else {
        from_value::<GetBalancesByAddressesRequest>(js_value)?
    };
    Ok(request)
});

declare! {
    IGetBalancesByAddressesResponse,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IBalancesByAddressesEntry {
        address : Address;
        balance : bigint;
    }
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IGetBalancesByAddressesResponse {
        entries : IBalancesByAddressesEntry[];
    }
    "#,
}

try_from! ( args: GetBalancesByAddressesResponse, IGetBalancesByAddressesResponse, {
    Ok(to_value(&args)?.into())
});

// ---

declare! {
    IGetBlockRequest,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IGetBlockRequest {
        hash : HexString;
        includeTransactions : boolean;
    }
    "#,
}

try_from! ( args: IGetBlockRequest, GetBlockRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetBlockResponse,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IGetBlockResponse {
        block : IBlock;
    }
    "#,
}

try_from! ( args: GetBlockResponse, IGetBlockResponse, {
    Ok(to_value(&args)?.into())
});

// ---

declare! {
    IGetBlocksRequest,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IGetBlocksRequest {
        lowHash? : HexString;
        includeBlocks : boolean;
        includeTransactions : boolean;
    }
    "#,
}

try_from! ( args: IGetBlocksRequest, GetBlocksRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetBlocksResponse,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IGetBlocksResponse {
        blockHashes : HexString[];
        blocks : IBlock[];
    }
    "#,
}

try_from! ( args: GetBlocksResponse, IGetBlocksResponse, {
    Ok(to_value(&args)?.into())
});

// ---

declare! {
    IGetBlockTemplateRequest,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IGetBlockTemplateRequest {
        payAddress : Address | string;
        /**
         * `extraData` can contain a user-supplied plain text or a byte array represented by `Uint8array`.
         */
        extraData? : string | Uint8Array;
    }
    "#,
}

try_from! ( args: IGetBlockTemplateRequest, GetBlockTemplateRequest, {
    let pay_address = args.cast_into::<Address>("payAddress")?;
    let extra_data = if let Some(extra_data) = args.try_get_value("extraData")? {
        if let Some(text) = extra_data.as_string() {
            text.into_bytes()
        } else {
            extra_data.try_as_vec_u8()?
        }
    } else {
        Default::default()
    };
    Ok(GetBlockTemplateRequest {
        pay_address,
        extra_data,
    })
});

declare! {
    IGetBlockTemplateResponse,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IGetBlockTemplateResponse {
        block : IRawBlock;
    }
    "#,
}

try_from! ( args: GetBlockTemplateResponse, IGetBlockTemplateResponse, {
    Ok(to_value(&args)?.into())
});

// ---

declare! {
    IGetCurrentBlockColorRequest,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IGetCurrentBlockColorRequest {
        hash: HexString;
    }
    "#,
}

try_from! ( args: IGetCurrentBlockColorRequest, GetCurrentBlockColorRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetCurrentBlockColorResponse,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IGetCurrentBlockColorResponse {
        blue: boolean;
    }
    "#,
}

try_from! ( args: GetCurrentBlockColorResponse, IGetCurrentBlockColorResponse, {
    Ok(to_value(&args)?.into())
});

// ---

declare! {
    IGetDaaScoreTimestampEstimateRequest,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IGetDaaScoreTimestampEstimateRequest {
        daaScores : bigint[];
    }
    "#,
}

try_from! ( args: IGetDaaScoreTimestampEstimateRequest, GetDaaScoreTimestampEstimateRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetDaaScoreTimestampEstimateResponse,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IGetDaaScoreTimestampEstimateResponse {
        timestamps : bigint[];
    }
    "#,
}

try_from! ( args: GetDaaScoreTimestampEstimateResponse, IGetDaaScoreTimestampEstimateResponse, {
    Ok(to_value(&args)?.into())
});

// ---

declare! {
    IGetCurrentNetworkRequest,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IGetCurrentNetworkRequest { }
    "#,
}

try_from! ( args: IGetCurrentNetworkRequest, GetCurrentNetworkRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetCurrentNetworkResponse,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IGetCurrentNetworkResponse {
        network : string;
    }
    "#,
}

try_from! ( args: GetCurrentNetworkResponse, IGetCurrentNetworkResponse, {
    Ok(to_value(&args)?.into())
});

// ---

declare! {
    IGetHeadersRequest,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IGetHeadersRequest {
        startHash : HexString;
        limit : bigint;
        isAscending : boolean;
    }
    "#,
}

try_from! ( args: IGetHeadersRequest, GetHeadersRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetHeadersResponse,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IGetHeadersResponse {
        headers : IHeader[];
    }
    "#,
}

try_from! ( args: GetHeadersResponse, IGetHeadersResponse, {
    Ok(to_value(&args)?.into())
});

// ---

declare! {
    IGetMempoolEntriesRequest,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IGetMempoolEntriesRequest {
        includeOrphanPool? : boolean;
        filterTransactionPool? : boolean;
    }
    "#,
}

try_from! ( args: IGetMempoolEntriesRequest, GetMempoolEntriesRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetMempoolEntriesResponse,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IGetMempoolEntriesResponse {
        mempoolEntries : IMempoolEntry[];
    }
    "#,
}

try_from! ( args: GetMempoolEntriesResponse, IGetMempoolEntriesResponse, {
    Ok(to_value(&args)?.into())
});

// ---

declare! {
    IGetMempoolEntriesByAddressesRequest,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IGetMempoolEntriesByAddressesRequest {
        addresses : Address[] | string[];
        includeOrphanPool? : boolean;
        filterTransactionPool? : boolean;
    }
    "#,
}

try_from! ( args: IGetMempoolEntriesByAddressesRequest, GetMempoolEntriesByAddressesRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetMempoolEntriesByAddressesResponse,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IGetMempoolEntriesByAddressesResponse {
        entries : IMempoolEntry[];
    }
    "#,
}

try_from! ( args: GetMempoolEntriesByAddressesResponse, IGetMempoolEntriesByAddressesResponse, {
    Ok(to_value(&args)?.into())
});

// ---

declare! {
    IGetMempoolEntryRequest,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IGetMempoolEntryRequest {
        transactionId : HexString;
        includeOrphanPool? : boolean;
        filterTransactionPool? : boolean;
    }
    "#,
}

try_from! ( args: IGetMempoolEntryRequest, GetMempoolEntryRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetMempoolEntryResponse,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IGetMempoolEntryResponse {
        mempoolEntry : IMempoolEntry;
    }
    "#,
}

try_from! ( args: GetMempoolEntryResponse, IGetMempoolEntryResponse, {
    Ok(to_value(&args)?.into())
});

// ---

declare! {
    IGetSubnetworkRequest,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IGetSubnetworkRequest {
        subnetworkId : HexString;
    }
    "#,
}

try_from! ( args: IGetSubnetworkRequest, GetSubnetworkRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetSubnetworkResponse,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IGetSubnetworkResponse {
        gasLimit : bigint;
    }
    "#,
}

try_from! ( args: GetSubnetworkResponse, IGetSubnetworkResponse, {
    Ok(to_value(&args)?.into())
});

// ---

declare! {
    IGetUtxosByAddressesRequest,
    "IGetUtxosByAddressesRequest | Address[] | string[]",
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IGetUtxosByAddressesRequest { 
        addresses : Address[] | string[]
    }
    "#,
}

try_from! ( args: IGetUtxosByAddressesRequest, GetUtxosByAddressesRequest, {
    let js_value = JsValue::from(args);
    let request = if let Ok(addresses) = Vec::<Address>::try_from(AddressOrStringArrayT::from(js_value.clone())) {
        GetUtxosByAddressesRequest { addresses }
    } else {
        from_value::<GetUtxosByAddressesRequest>(js_value)?
    };
    Ok(request)
});

declare! {
    IGetUtxosByAddressesResponse,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IGetUtxosByAddressesResponse {
        entries : UtxoEntryReference[];
    }
    "#,
}

try_from! ( args: GetUtxosByAddressesResponse, IGetUtxosByAddressesResponse, {
    let GetUtxosByAddressesResponse { entries } = args;
    let entries = entries.into_iter().map(UtxoEntryReference::from).collect::<Vec<UtxoEntryReference>>();
    let entries = js_sys::Array::from_iter(entries.into_iter().map(JsValue::from));
    let response = IGetUtxosByAddressesResponse::default();
    response.set("entries", entries.as_ref())?;
    Ok(response)
});

// ---

declare! {
    IGetVirtualChainFromBlockRequest,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IGetVirtualChainFromBlockRequest {
        startHash : HexString;
        includeAcceptedTransactionIds: boolean;
    }
    "#,
}

try_from! ( args: IGetVirtualChainFromBlockRequest, GetVirtualChainFromBlockRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetVirtualChainFromBlockResponse,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IGetVirtualChainFromBlockResponse {
        removedChainBlockHashes : HexString[];
        addedChainBlockHashes : HexString[];
        acceptedTransactionIds : IAcceptedTransactionIds[];
    }
    "#,
}

try_from! ( args: GetVirtualChainFromBlockResponse, IGetVirtualChainFromBlockResponse, {
    Ok(to_value(&args)?.into())
});

// ---

declare! {
    IResolveFinalityConflictRequest,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IResolveFinalityConflictRequest {
        finalityBlockHash: HexString;
    }
    "#,
}

try_from! ( args: IResolveFinalityConflictRequest, ResolveFinalityConflictRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IResolveFinalityConflictResponse,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IResolveFinalityConflictResponse { }
    "#,
}

try_from! ( args: ResolveFinalityConflictResponse, IResolveFinalityConflictResponse, {
    Ok(to_value(&args)?.into())
});

// ---

declare! {
    ISubmitBlockRequest,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface ISubmitBlockRequest {
        block : IRawBlock;
        allowNonDAABlocks: boolean;
    }
    "#,
}

try_from! ( args: ISubmitBlockRequest, SubmitBlockRequest, {
    Ok(from_value(args.into())?)
});

#[wasm_bindgen(typescript_custom_section)]
const TS_SUBMIT_BLOCK_REPORT: &'static str = r#"
    /**
     * 
     * @category Node RPC
     */
    export enum SubmitBlockRejectReason {
        /**
         * The block is invalid.
         */
        BlockInvalid = "BlockInvalid",
        /**
         * The node is not synced.
         */
        IsInIBD = "IsInIBD",
        /**
         * Route is full.
         */
        RouteIsFull = "RouteIsFull",
    }

    /**
     * 
     * @category Node RPC
     */
    export interface ISubmitBlockReport {
        type : "success" | "reject";
        reason? : SubmitBlockRejectReason;
    }
"#;

declare! {
    ISubmitBlockResponse,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface ISubmitBlockResponse {
        report : ISubmitBlockReport;
    }
    "#,
}

try_from! ( args: SubmitBlockResponse, ISubmitBlockResponse, {
    Ok(to_value(&args)?.into())
});

// ---

declare! {
    ISubmitTransactionReplacementRequest,
    // "ISubmitTransactionRequest | Transaction",
    r#"
    /**
     * Submit transaction replacement to the node.
     * 
     * @category Node RPC
     */
    export interface ISubmitTransactionReplacementRequest {
        transaction : Transaction,
    }
    "#,
}

try_from! ( args: ISubmitTransactionReplacementRequest, SubmitTransactionReplacementRequest, {
    let transaction = if let Some(transaction) = args.try_get_value("transaction")? {
        transaction
    } else {
        args.into()
    };

    let request = if let Ok(transaction) = Transaction::try_owned_from(&transaction) {
        SubmitTransactionReplacementRequest {
            transaction : transaction.into(),
        }
    } else {
        from_value(transaction)?
    };
    Ok(request)
});

declare! {
    ISubmitTransactionReplacementResponse,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface ISubmitTransactionReplacementResponse {
        transactionId : HexString;
        replacedTransaction: Transaction;
    }
    "#,
}

try_from! ( args: SubmitTransactionReplacementResponse, ISubmitTransactionReplacementResponse, {
    let transaction_id = args.transaction_id;
    let replaced_transaction  = cctx::Transaction::try_from(args.replaced_transaction)?;
    let replaced_transaction = Transaction::from(replaced_transaction);

    let response = ISubmitTransactionReplacementResponse::default();
    response.set("transactionId", &transaction_id.into())?;
    response.set("replacedTransaction", &replaced_transaction.into())?;
    Ok(response)
});

// ---

declare! {
    ISubmitTransactionRequest,
    // "ISubmitTransactionRequest | Transaction",
    r#"
    /**
     * Submit transaction to the node.
     * 
     * @category Node RPC
     */
    export interface ISubmitTransactionRequest {
        transaction : Transaction,
        allowOrphan? : boolean
    }
    "#,
}

try_from! ( args: ISubmitTransactionRequest, SubmitTransactionRequest, {
    let (transaction, allow_orphan) = if let Some(transaction) = args.try_get_value("transaction")? {
        let allow_orphan = args.try_get_bool("allowOrphan")?.unwrap_or(false);
        (transaction, allow_orphan)
    } else {
        (args.into(), false)
    };

    let request = if let Ok(transaction) = Transaction::try_owned_from(&transaction) {
        SubmitTransactionRequest {
            transaction : transaction.into(),
            allow_orphan,
        }
    } else {
        let tx = Transaction::try_cast_from(&transaction)?;
        SubmitTransactionRequest {
            transaction : tx.as_ref().into(),
            allow_orphan,
        }
    };
    Ok(request)
});

declare! {
    ISubmitTransactionResponse,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface ISubmitTransactionResponse {
        transactionId : HexString;
    }
    "#,
}

try_from! ( args: SubmitTransactionResponse, ISubmitTransactionResponse, {
    Ok(to_value(&args)?.into())
});

// ---

declare! {
    IUnbanRequest,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IUnbanRequest {
        /**
         * IPv4 or IPv6 address to unban.
         */
        ip : string;
    }
    "#,
}

try_from! ( args: IUnbanRequest, UnbanRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IUnbanResponse,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IUnbanResponse { }
    "#,
}

try_from! ( args: UnbanResponse, IUnbanResponse, {
    Ok(to_value(&args)?.into())
});

// ---

declare! {
    IFeerateBucket,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IFeerateBucket {
        /**
         * The fee/mass ratio estimated to be required for inclusion time <= estimated_seconds
         */
        feerate : number;
        /**
         * The estimated inclusion time for a transaction with fee/mass = feerate
         */
        estimatedSeconds : number;
    }
    "#,
}

declare! {
    IFeeEstimate,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IFeeEstimate {
        /**
         * *Top-priority* feerate bucket. Provides an estimation of the feerate required for sub-second DAG inclusion.
         *
         * Note: for all buckets, feerate values represent fee/mass of a transaction in `sompi/gram` units.
         * Given a feerate value recommendation, calculate the required fee by
         * taking the transaction mass and multiplying it by feerate: `fee = feerate * mass(tx)`
         */

        priorityBucket : IFeerateBucket;
        /**
         * A vector of *normal* priority feerate values. The first value of this vector is guaranteed to exist and
         * provide an estimation for sub-*minute* DAG inclusion. All other values will have shorter estimation
         * times than all `low_bucket` values. Therefor by chaining `[priority] | normal | low` and interpolating
         * between them, one can compose a complete feerate function on the client side. The API makes an effort
         * to sample enough "interesting" points on the feerate-to-time curve, so that the interpolation is meaningful.
         */

        normalBuckets : IFeerateBucket[];
        /**
        * An array of *low* priority feerate values. The first value of this vector is guaranteed to
        * exist and provide an estimation for sub-*hour* DAG inclusion.
        */
        lowBuckets : IFeerateBucket[];
    }
    "#,
}

try_from!( estimate: RpcFeeEstimate, IFeeEstimate, {

    let priority_bucket = IFeerateBucket::default();
    priority_bucket.set("feerate", &estimate.priority_bucket.feerate.into())?;
    priority_bucket.set("estimatedSeconds", &estimate.priority_bucket.estimated_seconds.into())?;

    let normal_buckets = estimate.normal_buckets.into_iter().map(|normal_bucket| {
        let bucket = IFeerateBucket::default();
        bucket.set("feerate", &normal_bucket.feerate.into())?;
        bucket.set("estimatedSeconds", &normal_bucket.estimated_seconds.into())?;
        Ok(bucket)
    }).collect::<Result<Vec<IFeerateBucket>>>()?;

    let low_buckets = estimate.low_buckets.into_iter().map(|low_bucket| {
        let bucket = IFeerateBucket::default();
        bucket.set("feerate", &low_bucket.feerate.into())?;
        bucket.set("estimatedSeconds", &low_bucket.estimated_seconds.into())?;
        Ok(bucket)
    }).collect::<Result<Vec<IFeerateBucket>>>()?;

    let estimate = IFeeEstimate::default();
    estimate.set("priorityBucket", &priority_bucket)?;
    estimate.set("normalBuckets", &js_sys::Array::from_iter(normal_buckets))?;
    estimate.set("lowBuckets", &js_sys::Array::from_iter(low_buckets))?;

    Ok(estimate)
});

// ---

declare! {
    IGetFeeEstimateRequest,
    r#"
    /**
     * Get fee estimate from the node.
     * 
     * @category Node RPC
     */
    export interface IGetFeeEstimateRequest { }
    "#,
}

try_from! ( args: IGetFeeEstimateRequest, GetFeeEstimateRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetFeeEstimateResponse,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IGetFeeEstimateResponse {
        estimate : IFeeEstimate;
    }
    "#,
}

try_from!( args: GetFeeEstimateResponse, IGetFeeEstimateResponse, {
    let estimate = IFeeEstimate::try_from(args.estimate)?;
    let response = IGetFeeEstimateResponse::default();
    response.set("estimate", &estimate)?;
    Ok(response)
});

// ---

declare! {
    IFeeEstimateVerboseExperimentalData,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IFeeEstimateVerboseExperimentalData {
        mempoolReadyTransactionsCount : bigint;
        mempoolReadyTransactionsTotalMass : bigint;
        networkMassPerSecond : bigint;
        nextBlockTemplateFeerateMin : number;
        nextBlockTemplateFeerateMedian : number;
        nextBlockTemplateFeerateMax : number;
        minimumRelayFeerate? : number;
        payloadOvercapFeerateFloor? : number;
        effectiveHfaFeerateFloor? : number;
    }
    "#,
}

try_from!( data: RpcFeeEstimateVerboseExperimentalData, IFeeEstimateVerboseExperimentalData, {

    let target = IFeeEstimateVerboseExperimentalData::default();
    target.set("mempoolReadyTransactionsCount", &js_sys::BigInt::from(data.mempool_ready_transactions_count).into())?;
    target.set("mempoolReadyTransactionsTotalMass", &js_sys::BigInt::from(data.mempool_ready_transactions_total_mass).into())?;
    target.set("networkMassPerSecond", &js_sys::BigInt::from(data.network_mass_per_second).into())?;
    target.set("nextBlockTemplateFeerateMin", &data.next_block_template_feerate_min.into())?;
    target.set("nextBlockTemplateFeerateMedian", &data.next_block_template_feerate_median.into())?;
    target.set("nextBlockTemplateFeerateMax", &data.next_block_template_feerate_max.into())?;
    if let Some(minimum_relay_feerate) = data.minimum_relay_feerate {
        target.set("minimumRelayFeerate", &minimum_relay_feerate.into())?;
    }
    if let Some(payload_overcap_feerate_floor) = data.payload_overcap_feerate_floor {
        target.set("payloadOvercapFeerateFloor", &payload_overcap_feerate_floor.into())?;
    }
    if let Some(effective_hfa_feerate_floor) = data.effective_hfa_feerate_floor {
        target.set("effectiveHfaFeerateFloor", &effective_hfa_feerate_floor.into())?;
    }

    Ok(target)
});

declare! {
    IGetFeeEstimateExperimentalRequest,
    // "ISubmitTransactionRequest | Transaction",
    r#"
    /**
     * Get fee estimate from the node.
     * 
     * @category Node RPC
     */
    export interface IGetFeeEstimateExperimentalRequest { }
    "#,
}

try_from! ( args: IGetFeeEstimateExperimentalRequest, GetFeeEstimateExperimentalRequest, {
    Ok(from_value(args.into())?)
});

declare! {
    IGetFeeEstimateExperimentalResponse,
    r#"
    /**
     * 
     * 
     * @category Node RPC
     */
    export interface IGetFeeEstimateExperimentalResponse {
        estimate : IFeeEstimate;
        verbose? : IFeeEstimateVerboseExperimentalData
    }
    "#,
}

try_from!( args: GetFeeEstimateExperimentalResponse, IGetFeeEstimateExperimentalResponse, {
    let estimate = IFeeEstimate::try_from(args.estimate)?;
    let response = IGetFeeEstimateExperimentalResponse::default();
    response.set("estimate", &estimate)?;

    if let Some(verbose) = args.verbose {
        let verbose = IFeeEstimateVerboseExperimentalData::try_from(verbose)?;
        response.set("verbose", &verbose)?;
    }

    Ok(response)
});

// ---
