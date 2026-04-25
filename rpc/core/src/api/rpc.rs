//! The client API
//!
//! Rpc = External RPC Service
//! All data provided by the RCP server can be trusted by the client
//! No data submitted by the client to the server can be trusted

use crate::api::connection::DynRpcConnection;
use crate::{model::*, notify::connection::ChannelConnection, RpcResult};
use async_trait::async_trait;
use cryptix_notify::{listener::ListenerId, scope::Scope, subscription::Command};
use downcast::{downcast_sync, AnySync};
use std::sync::Arc;

pub const MAX_SAFE_WINDOW_SIZE: u32 = 10_000;

/// Client RPC Api
///
/// The [`RpcApi`] trait defines RPC calls taking a request message as unique parameter.
///
/// For each RPC call a matching readily implemented function taking detailed parameters is also provided.
#[async_trait]
pub trait RpcApi: Sync + Send + AnySync {
    ///
    async fn ping(&self) -> RpcResult<()> {
        self.ping_call(None, PingRequest {}).await?;
        Ok(())
    }
    async fn ping_call(&self, connection: Option<&DynRpcConnection>, request: PingRequest) -> RpcResult<PingResponse>;

    // ---

    async fn get_system_info(&self) -> RpcResult<GetSystemInfoResponse> {
        Ok(self.get_system_info_call(None, GetSystemInfoRequest {}).await?)
    }
    async fn get_system_info_call(
        &self,
        connection: Option<&DynRpcConnection>,
        request: GetSystemInfoRequest,
    ) -> RpcResult<GetSystemInfoResponse>;

    // ---

    async fn get_connections(&self, include_profile_data: bool) -> RpcResult<GetConnectionsResponse> {
        self.get_connections_call(None, GetConnectionsRequest { include_profile_data }).await
    }
    async fn get_connections_call(
        &self,
        connection: Option<&DynRpcConnection>,
        request: GetConnectionsRequest,
    ) -> RpcResult<GetConnectionsResponse>;

    // ---

    async fn get_metrics(
        &self,
        process_metrics: bool,
        connection_metrics: bool,
        bandwidth_metrics: bool,
        consensus_metrics: bool,
        storage_metrics: bool,
        custom_metrics: bool,
    ) -> RpcResult<GetMetricsResponse> {
        self.get_metrics_call(
            None,
            GetMetricsRequest {
                process_metrics,
                connection_metrics,
                bandwidth_metrics,
                consensus_metrics,
                storage_metrics,
                custom_metrics,
            },
        )
        .await
    }
    async fn get_metrics_call(
        &self,
        connection: Option<&DynRpcConnection>,
        request: GetMetricsRequest,
    ) -> RpcResult<GetMetricsResponse>;

    // get_info alternative that carries only version, network_id (full), is_synced, virtual_daa_score
    // these are the only variables needed to negotiate a wRPC connection (besides the wRPC handshake)
    async fn get_server_info(&self) -> RpcResult<GetServerInfoResponse> {
        self.get_server_info_call(None, GetServerInfoRequest {}).await
    }
    async fn get_server_info_call(
        &self,
        connection: Option<&DynRpcConnection>,
        request: GetServerInfoRequest,
    ) -> RpcResult<GetServerInfoResponse>;

    // Get current sync status of the node (should be converted to a notification subscription)
    async fn get_sync_status(&self) -> RpcResult<bool> {
        Ok(self.get_sync_status_call(None, GetSyncStatusRequest {}).await?.is_synced)
    }
    async fn get_sync_status_call(
        &self,
        connection: Option<&DynRpcConnection>,
        request: GetSyncStatusRequest,
    ) -> RpcResult<GetSyncStatusResponse>;

    // Get strong-nodes overlay state and announced entries.
    async fn get_strong_nodes(&self) -> RpcResult<GetStrongNodesResponse> {
        self.get_strong_nodes_call(None, GetStrongNodesRequest {}).await
    }
    async fn get_strong_nodes_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetStrongNodesRequest,
    ) -> RpcResult<GetStrongNodesResponse> {
        Err(crate::RpcError::NotImplemented)
    }

    // Simulate a Cryptix Atomic token operation (best-effort hint, non-mutating, not a strict 1:1 execution preflight).
    async fn simulate_token_op(&self, request: SimulateTokenOpRequest) -> RpcResult<SimulateTokenOpResponse> {
        self.simulate_token_op_call(None, request).await
    }
    async fn simulate_token_op_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: SimulateTokenOpRequest,
    ) -> RpcResult<SimulateTokenOpResponse> {
        Err(crate::RpcError::NotImplemented)
    }

    async fn get_token_balance(&self, request: GetTokenBalanceRequest) -> RpcResult<GetTokenBalanceResponse> {
        self.get_token_balance_call(None, request).await
    }
    async fn get_token_balance_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetTokenBalanceRequest,
    ) -> RpcResult<GetTokenBalanceResponse> {
        Err(crate::RpcError::NotImplemented)
    }

    async fn get_token_nonce(&self, request: GetTokenNonceRequest) -> RpcResult<GetTokenNonceResponse> {
        self.get_token_nonce_call(None, request).await
    }
    async fn get_token_nonce_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetTokenNonceRequest,
    ) -> RpcResult<GetTokenNonceResponse> {
        Err(crate::RpcError::NotImplemented)
    }

    async fn get_token_asset(&self, request: GetTokenAssetRequest) -> RpcResult<GetTokenAssetResponse> {
        self.get_token_asset_call(None, request).await
    }
    async fn get_token_asset_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetTokenAssetRequest,
    ) -> RpcResult<GetTokenAssetResponse> {
        Err(crate::RpcError::NotImplemented)
    }

    async fn get_token_op_status(&self, request: GetTokenOpStatusRequest) -> RpcResult<GetTokenOpStatusResponse> {
        self.get_token_op_status_call(None, request).await
    }
    async fn get_token_op_status_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetTokenOpStatusRequest,
    ) -> RpcResult<GetTokenOpStatusResponse> {
        Err(crate::RpcError::NotImplemented)
    }

    async fn get_token_state_hash(&self) -> RpcResult<GetTokenStateHashResponse> {
        self.get_token_state_hash_call(None, GetTokenStateHashRequest { at_block_hash: None }).await
    }
    async fn get_token_state_hash_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetTokenStateHashRequest,
    ) -> RpcResult<GetTokenStateHashResponse> {
        Err(crate::RpcError::NotImplemented)
    }

    async fn get_token_spendability(&self, request: GetTokenSpendabilityRequest) -> RpcResult<GetTokenSpendabilityResponse> {
        self.get_token_spendability_call(None, request).await
    }
    async fn get_token_spendability_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetTokenSpendabilityRequest,
    ) -> RpcResult<GetTokenSpendabilityResponse> {
        Err(crate::RpcError::NotImplemented)
    }

    async fn get_token_events(&self, request: GetTokenEventsRequest) -> RpcResult<GetTokenEventsResponse> {
        self.get_token_events_call(None, request).await
    }
    async fn get_token_events_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetTokenEventsRequest,
    ) -> RpcResult<GetTokenEventsResponse> {
        Err(crate::RpcError::NotImplemented)
    }

    async fn export_token_snapshot(&self, path: String) -> RpcResult<ExportTokenSnapshotResponse> {
        self.export_token_snapshot_call(None, ExportTokenSnapshotRequest { path }).await
    }
    async fn export_token_snapshot_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: ExportTokenSnapshotRequest,
    ) -> RpcResult<ExportTokenSnapshotResponse> {
        Err(crate::RpcError::NotImplemented)
    }

    async fn import_token_snapshot(&self, path: String) -> RpcResult<ImportTokenSnapshotResponse> {
        self.import_token_snapshot_call(None, ImportTokenSnapshotRequest { path }).await
    }
    async fn import_token_snapshot_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: ImportTokenSnapshotRequest,
    ) -> RpcResult<ImportTokenSnapshotResponse> {
        Err(crate::RpcError::NotImplemented)
    }

    async fn get_token_health(&self) -> RpcResult<GetTokenHealthResponse> {
        self.get_token_health_call(None, GetTokenHealthRequest { at_block_hash: None }).await
    }
    async fn get_token_health_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetTokenHealthRequest,
    ) -> RpcResult<GetTokenHealthResponse> {
        Err(crate::RpcError::NotImplemented)
    }

    async fn get_sc_bootstrap_sources(&self) -> RpcResult<GetScBootstrapSourcesResponse> {
        self.get_sc_bootstrap_sources_call(None, GetScBootstrapSourcesRequest {}).await
    }
    async fn get_sc_bootstrap_sources_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetScBootstrapSourcesRequest,
    ) -> RpcResult<GetScBootstrapSourcesResponse> {
        Err(crate::RpcError::NotImplemented)
    }

    async fn get_sc_snapshot_manifest(&self, snapshot_id: String) -> RpcResult<GetScSnapshotManifestResponse> {
        self.get_sc_snapshot_manifest_call(None, GetScSnapshotManifestRequest { snapshot_id }).await
    }
    async fn get_sc_snapshot_manifest_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetScSnapshotManifestRequest,
    ) -> RpcResult<GetScSnapshotManifestResponse> {
        Err(crate::RpcError::NotImplemented)
    }

    async fn get_sc_snapshot_chunk(&self, request: GetScSnapshotChunkRequest) -> RpcResult<GetScSnapshotChunkResponse> {
        self.get_sc_snapshot_chunk_call(None, request).await
    }
    async fn get_sc_snapshot_chunk_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetScSnapshotChunkRequest,
    ) -> RpcResult<GetScSnapshotChunkResponse> {
        Err(crate::RpcError::NotImplemented)
    }

    async fn get_sc_replay_window_chunk(&self, request: GetScReplayWindowChunkRequest) -> RpcResult<GetScReplayWindowChunkResponse> {
        self.get_sc_replay_window_chunk_call(None, request).await
    }
    async fn get_sc_replay_window_chunk_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetScReplayWindowChunkRequest,
    ) -> RpcResult<GetScReplayWindowChunkResponse> {
        Err(crate::RpcError::NotImplemented)
    }

    async fn get_sc_snapshot_head(&self) -> RpcResult<GetScSnapshotHeadResponse> {
        self.get_sc_snapshot_head_call(None, GetScSnapshotHeadRequest {}).await
    }
    async fn get_sc_snapshot_head_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetScSnapshotHeadRequest,
    ) -> RpcResult<GetScSnapshotHeadResponse> {
        Err(crate::RpcError::NotImplemented)
    }

    async fn get_token_assets(&self, request: GetTokenAssetsRequest) -> RpcResult<GetTokenAssetsResponse> {
        self.get_token_assets_call(None, request).await
    }
    async fn get_token_assets_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetTokenAssetsRequest,
    ) -> RpcResult<GetTokenAssetsResponse> {
        Err(crate::RpcError::NotImplemented)
    }

    async fn get_token_balances_by_owner(
        &self,
        request: GetTokenBalancesByOwnerRequest,
    ) -> RpcResult<GetTokenBalancesByOwnerResponse> {
        self.get_token_balances_by_owner_call(None, request).await
    }
    async fn get_token_balances_by_owner_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetTokenBalancesByOwnerRequest,
    ) -> RpcResult<GetTokenBalancesByOwnerResponse> {
        Err(crate::RpcError::NotImplemented)
    }

    async fn get_token_holders(&self, request: GetTokenHoldersRequest) -> RpcResult<GetTokenHoldersResponse> {
        self.get_token_holders_call(None, request).await
    }
    async fn get_token_holders_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetTokenHoldersRequest,
    ) -> RpcResult<GetTokenHoldersResponse> {
        Err(crate::RpcError::NotImplemented)
    }

    async fn get_token_owner_id_by_address(
        &self,
        request: GetTokenOwnerIdByAddressRequest,
    ) -> RpcResult<GetTokenOwnerIdByAddressResponse> {
        self.get_token_owner_id_by_address_call(None, request).await
    }
    async fn get_token_owner_id_by_address_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetTokenOwnerIdByAddressRequest,
    ) -> RpcResult<GetTokenOwnerIdByAddressResponse> {
        Err(crate::RpcError::NotImplemented)
    }

    async fn get_liquidity_pool_state(&self, request: GetLiquidityPoolStateRequest) -> RpcResult<GetLiquidityPoolStateResponse> {
        self.get_liquidity_pool_state_call(None, request).await
    }
    async fn get_liquidity_pool_state_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetLiquidityPoolStateRequest,
    ) -> RpcResult<GetLiquidityPoolStateResponse> {
        Err(crate::RpcError::NotImplemented)
    }

    async fn get_liquidity_quote(&self, request: GetLiquidityQuoteRequest) -> RpcResult<GetLiquidityQuoteResponse> {
        self.get_liquidity_quote_call(None, request).await
    }
    async fn get_liquidity_quote_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetLiquidityQuoteRequest,
    ) -> RpcResult<GetLiquidityQuoteResponse> {
        Err(crate::RpcError::NotImplemented)
    }

    async fn get_liquidity_fee_state(&self, request: GetLiquidityFeeStateRequest) -> RpcResult<GetLiquidityFeeStateResponse> {
        self.get_liquidity_fee_state_call(None, request).await
    }
    async fn get_liquidity_fee_state_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetLiquidityFeeStateRequest,
    ) -> RpcResult<GetLiquidityFeeStateResponse> {
        Err(crate::RpcError::NotImplemented)
    }

    async fn get_liquidity_claim_preview(
        &self,
        request: GetLiquidityClaimPreviewRequest,
    ) -> RpcResult<GetLiquidityClaimPreviewResponse> {
        self.get_liquidity_claim_preview_call(None, request).await
    }
    async fn get_liquidity_claim_preview_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetLiquidityClaimPreviewRequest,
    ) -> RpcResult<GetLiquidityClaimPreviewResponse> {
        Err(crate::RpcError::NotImplemented)
    }

    async fn get_liquidity_holders(&self, request: GetLiquidityHoldersRequest) -> RpcResult<GetLiquidityHoldersResponse> {
        self.get_liquidity_holders_call(None, request).await
    }
    async fn get_liquidity_holders_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetLiquidityHoldersRequest,
    ) -> RpcResult<GetLiquidityHoldersResponse> {
        Err(crate::RpcError::NotImplemented)
    }

    // ---

    /// Requests the network the node is currently running against.
    async fn get_current_network(&self) -> RpcResult<RpcNetworkType> {
        Ok(self.get_current_network_call(None, GetCurrentNetworkRequest {}).await?.network)
    }
    async fn get_current_network_call(
        &self,
        connection: Option<&DynRpcConnection>,
        request: GetCurrentNetworkRequest,
    ) -> RpcResult<GetCurrentNetworkResponse>;

    /// Submit a block into the DAG.
    ///
    /// Blocks are generally expected to have been generated using the get_block_template call.
    async fn submit_block(&self, block: RpcRawBlock, allow_non_daa_blocks: bool) -> RpcResult<SubmitBlockResponse> {
        self.submit_block_call(None, SubmitBlockRequest::new(block, allow_non_daa_blocks)).await
    }
    async fn submit_block_call(
        &self,
        connection: Option<&DynRpcConnection>,
        request: SubmitBlockRequest,
    ) -> RpcResult<SubmitBlockResponse>;

    /// Request a current block template.
    ///
    /// Callers are expected to solve the block template and submit it using the submit_block call.
    async fn get_block_template(&self, pay_address: RpcAddress, extra_data: RpcExtraData) -> RpcResult<GetBlockTemplateResponse> {
        self.get_block_template_call(None, GetBlockTemplateRequest::new(pay_address, extra_data)).await
    }
    async fn get_block_template_call(
        &self,
        connection: Option<&DynRpcConnection>,
        request: GetBlockTemplateRequest,
    ) -> RpcResult<GetBlockTemplateResponse>;

    /// Requests the list of known cryptixd addresses in the current network (mainnet, testnet, etc.)
    async fn get_peer_addresses(&self) -> RpcResult<GetPeerAddressesResponse> {
        self.get_peer_addresses_call(None, GetPeerAddressesRequest {}).await
    }
    async fn get_peer_addresses_call(
        &self,
        connection: Option<&DynRpcConnection>,
        request: GetPeerAddressesRequest,
    ) -> RpcResult<GetPeerAddressesResponse>;

    /// requests the hash of the current virtual's selected parent.
    async fn get_sink(&self) -> RpcResult<GetSinkResponse> {
        self.get_sink_call(None, GetSinkRequest {}).await
    }
    async fn get_sink_call(&self, connection: Option<&DynRpcConnection>, request: GetSinkRequest) -> RpcResult<GetSinkResponse>;

    /// Requests information about a specific transaction in the mempool.
    async fn get_mempool_entry(
        &self,
        transaction_id: RpcTransactionId,
        include_orphan_pool: bool,
        filter_transaction_pool: bool,
    ) -> RpcResult<RpcMempoolEntry> {
        Ok(self
            .get_mempool_entry_call(None, GetMempoolEntryRequest::new(transaction_id, include_orphan_pool, filter_transaction_pool))
            .await?
            .mempool_entry)
    }
    async fn get_mempool_entry_call(
        &self,
        connection: Option<&DynRpcConnection>,
        request: GetMempoolEntryRequest,
    ) -> RpcResult<GetMempoolEntryResponse>;

    /// Requests information about all the transactions currently in the mempool.
    async fn get_mempool_entries(&self, include_orphan_pool: bool, filter_transaction_pool: bool) -> RpcResult<Vec<RpcMempoolEntry>> {
        Ok(self
            .get_mempool_entries_call(None, GetMempoolEntriesRequest::new(include_orphan_pool, filter_transaction_pool))
            .await?
            .mempool_entries)
    }
    async fn get_mempool_entries_call(
        &self,
        connection: Option<&DynRpcConnection>,
        request: GetMempoolEntriesRequest,
    ) -> RpcResult<GetMempoolEntriesResponse>;

    /// requests information about all the p2p peers currently connected to this node.
    async fn get_connected_peer_info(&self) -> RpcResult<GetConnectedPeerInfoResponse> {
        self.get_connected_peer_info_call(None, GetConnectedPeerInfoRequest {}).await
    }
    async fn get_connected_peer_info_call(
        &self,
        connection: Option<&DynRpcConnection>,
        request: GetConnectedPeerInfoRequest,
    ) -> RpcResult<GetConnectedPeerInfoResponse>;

    /// Adds a peer to the node's outgoing connection list.
    ///
    /// This will, in most cases, result in the node connecting to said peer.
    async fn add_peer(&self, peer_address: RpcContextualPeerAddress, is_permanent: bool) -> RpcResult<()> {
        self.add_peer_call(None, AddPeerRequest::new(peer_address, is_permanent)).await?;
        Ok(())
    }
    async fn add_peer_call(&self, connection: Option<&DynRpcConnection>, request: AddPeerRequest) -> RpcResult<AddPeerResponse>;

    /// Submits a transaction to the mempool.
    async fn submit_transaction(&self, transaction: RpcTransaction, allow_orphan: bool) -> RpcResult<RpcTransactionId> {
        Ok(self.submit_transaction_call(None, SubmitTransactionRequest { transaction, allow_orphan }).await?.transaction_id)
    }
    async fn submit_transaction_call(
        &self,
        connection: Option<&DynRpcConnection>,
        request: SubmitTransactionRequest,
    ) -> RpcResult<SubmitTransactionResponse>;

    /// Submits a transaction replacement to the mempool, applying a mandatory Replace by Fee policy.
    ///
    /// Returns the ID of the inserted transaction and the transaction the submission replaced in the mempool.
    async fn submit_transaction_replacement(&self, transaction: RpcTransaction) -> RpcResult<SubmitTransactionReplacementResponse> {
        self.submit_transaction_replacement_call(None, SubmitTransactionReplacementRequest { transaction }).await
    }
    async fn submit_transaction_replacement_call(
        &self,
        connection: Option<&DynRpcConnection>,
        request: SubmitTransactionReplacementRequest,
    ) -> RpcResult<SubmitTransactionReplacementResponse>;

    /// Submits a fast rail intent.
    async fn submit_fast_intent(
        &self,
        base_tx: RpcTransaction,
        intent_nonce: u64,
        client_created_at_ms: u64,
        max_fee: u64,
    ) -> RpcResult<SubmitFastIntentResponse> {
        self.submit_fast_intent_call(None, SubmitFastIntentRequest { base_tx, intent_nonce, client_created_at_ms, max_fee }).await
    }
    async fn submit_fast_intent_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: SubmitFastIntentRequest,
    ) -> RpcResult<SubmitFastIntentResponse> {
        Err(crate::RpcError::NotImplemented)
    }

    /// Returns the local status of a fast rail intent.
    async fn get_fast_intent_status(
        &self,
        intent_id: RpcHash,
        client_last_node_epoch: Option<u64>,
    ) -> RpcResult<GetFastIntentStatusResponse> {
        self.get_fast_intent_status_call(None, GetFastIntentStatusRequest { intent_id, client_last_node_epoch }).await
    }
    async fn get_fast_intent_status_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetFastIntentStatusRequest,
    ) -> RpcResult<GetFastIntentStatusResponse> {
        Err(crate::RpcError::NotImplemented)
    }

    /// Cancels a local fast rail intent context.
    async fn cancel_fast_intent(
        &self,
        intent_id: RpcHash,
        cancel_token: String,
        node_epoch: u64,
    ) -> RpcResult<CancelFastIntentResponse> {
        self.cancel_fast_intent_call(None, CancelFastIntentRequest { intent_id, cancel_token, node_epoch }).await
    }
    async fn cancel_fast_intent_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: CancelFastIntentRequest,
    ) -> RpcResult<CancelFastIntentResponse> {
        Err(crate::RpcError::NotImplemented)
    }

    /// Requests information about a specific block.
    async fn get_block(&self, hash: RpcHash, include_transactions: bool) -> RpcResult<RpcBlock> {
        Ok(self.get_block_call(None, GetBlockRequest::new(hash, include_transactions)).await?.block)
    }
    async fn get_block_call(&self, connection: Option<&DynRpcConnection>, request: GetBlockRequest) -> RpcResult<GetBlockResponse>;

    /// Requests information about a specific subnetwork.
    async fn get_subnetwork(&self, subnetwork_id: RpcSubnetworkId) -> RpcResult<GetSubnetworkResponse> {
        self.get_subnetwork_call(None, GetSubnetworkRequest::new(subnetwork_id)).await
    }
    async fn get_subnetwork_call(
        &self,
        connection: Option<&DynRpcConnection>,
        request: GetSubnetworkRequest,
    ) -> RpcResult<GetSubnetworkResponse>;

    /// Requests the virtual selected parent chain from some `start_hash` to this node's current virtual.
    async fn get_virtual_chain_from_block(
        &self,
        start_hash: RpcHash,
        include_accepted_transaction_ids: bool,
    ) -> RpcResult<GetVirtualChainFromBlockResponse> {
        self.get_virtual_chain_from_block_call(
            None,
            GetVirtualChainFromBlockRequest::new(start_hash, include_accepted_transaction_ids),
        )
        .await
    }
    async fn get_virtual_chain_from_block_call(
        &self,
        connection: Option<&DynRpcConnection>,
        request: GetVirtualChainFromBlockRequest,
    ) -> RpcResult<GetVirtualChainFromBlockResponse>;

    /// Requests blocks between a certain block `low_hash` up to this node's current virtual.
    async fn get_blocks(
        &self,
        low_hash: Option<RpcHash>,
        include_blocks: bool,
        include_transactions: bool,
    ) -> RpcResult<GetBlocksResponse> {
        self.get_blocks_call(None, GetBlocksRequest::new(low_hash, include_blocks, include_transactions)).await
    }
    async fn get_blocks_call(&self, connection: Option<&DynRpcConnection>, request: GetBlocksRequest) -> RpcResult<GetBlocksResponse>;

    /// Requests the current number of blocks in this node.
    ///
    /// Note that this number may decrease as pruning occurs.
    async fn get_block_count(&self) -> RpcResult<GetBlockCountResponse> {
        self.get_block_count_call(None, GetBlockCountRequest {}).await
    }
    async fn get_block_count_call(
        &self,
        connection: Option<&DynRpcConnection>,
        request: GetBlockCountRequest,
    ) -> RpcResult<GetBlockCountResponse>;

    /// Requests general information about the current state of this node's DAG.
    async fn get_block_dag_info(&self) -> RpcResult<GetBlockDagInfoResponse> {
        self.get_block_dag_info_call(None, GetBlockDagInfoRequest {}).await
    }
    async fn get_block_dag_info_call(
        &self,
        connection: Option<&DynRpcConnection>,
        request: GetBlockDagInfoRequest,
    ) -> RpcResult<GetBlockDagInfoResponse>;

    ///
    async fn resolve_finality_conflict(&self, finality_block_hash: RpcHash) -> RpcResult<()> {
        self.resolve_finality_conflict_call(None, ResolveFinalityConflictRequest::new(finality_block_hash)).await?;
        Ok(())
    }
    async fn resolve_finality_conflict_call(
        &self,
        connection: Option<&DynRpcConnection>,
        request: ResolveFinalityConflictRequest,
    ) -> RpcResult<ResolveFinalityConflictResponse>;

    /// Shuts down this node.
    async fn shutdown(&self) -> RpcResult<()> {
        self.shutdown_call(None, ShutdownRequest {}).await?;
        Ok(())
    }
    async fn shutdown_call(&self, connection: Option<&DynRpcConnection>, request: ShutdownRequest) -> RpcResult<ShutdownResponse>;

    /// Requests headers between the given `start_hash` and the current virtual, up to the given limit.
    async fn get_headers(&self, start_hash: RpcHash, limit: u64, is_ascending: bool) -> RpcResult<Vec<RpcHeader>> {
        Ok(self.get_headers_call(None, GetHeadersRequest::new(start_hash, limit, is_ascending)).await?.headers)
    }
    async fn get_headers_call(
        &self,
        connection: Option<&DynRpcConnection>,
        request: GetHeadersRequest,
    ) -> RpcResult<GetHeadersResponse>;

    /// Returns the total balance in unspent transactions towards a given address.
    ///
    /// This call is only available when this node was started with `--utxoindex`.
    async fn get_balance_by_address(&self, address: RpcAddress) -> RpcResult<u64> {
        Ok(self.get_balance_by_address_call(None, GetBalanceByAddressRequest::new(address)).await?.balance)
    }
    async fn get_balance_by_address_call(
        &self,
        connection: Option<&DynRpcConnection>,
        request: GetBalanceByAddressRequest,
    ) -> RpcResult<GetBalanceByAddressResponse>;

    ///
    async fn get_balances_by_addresses(&self, addresses: Vec<RpcAddress>) -> RpcResult<Vec<RpcBalancesByAddressesEntry>> {
        Ok(self.get_balances_by_addresses_call(None, GetBalancesByAddressesRequest::new(addresses)).await?.entries)
    }
    async fn get_balances_by_addresses_call(
        &self,
        connection: Option<&DynRpcConnection>,
        request: GetBalancesByAddressesRequest,
    ) -> RpcResult<GetBalancesByAddressesResponse>;

    /// Requests all current UTXOs for the given node addresses.
    ///
    /// This call is only available when this node was started with `--utxoindex`.
    async fn get_utxos_by_addresses(&self, addresses: Vec<RpcAddress>) -> RpcResult<Vec<RpcUtxosByAddressesEntry>> {
        Ok(self.get_utxos_by_addresses_call(None, GetUtxosByAddressesRequest::new(addresses)).await?.entries)
    }
    async fn get_utxos_by_addresses_call(
        &self,
        connection: Option<&DynRpcConnection>,
        request: GetUtxosByAddressesRequest,
    ) -> RpcResult<GetUtxosByAddressesResponse>;

    /// Requests the blue score of the current selected parent of the virtual block.
    async fn get_sink_blue_score(&self) -> RpcResult<u64> {
        Ok(self.get_sink_blue_score_call(None, GetSinkBlueScoreRequest {}).await?.blue_score)
    }
    async fn get_sink_blue_score_call(
        &self,
        connection: Option<&DynRpcConnection>,
        request: GetSinkBlueScoreRequest,
    ) -> RpcResult<GetSinkBlueScoreResponse>;

    /// Bans the given ip.
    async fn ban(&self, ip: RpcIpAddress) -> RpcResult<()> {
        self.ban_call(None, BanRequest::new(ip)).await?;
        Ok(())
    }
    async fn ban_call(&self, connection: Option<&DynRpcConnection>, request: BanRequest) -> RpcResult<BanResponse>;

    /// Unbans the given ip.
    async fn unban(&self, ip: RpcIpAddress) -> RpcResult<()> {
        self.unban_call(None, UnbanRequest::new(ip)).await?;
        Ok(())
    }
    async fn unban_call(&self, connection: Option<&DynRpcConnection>, request: UnbanRequest) -> RpcResult<UnbanResponse>;

    /// Returns info about the node.
    async fn get_info(&self) -> RpcResult<GetInfoResponse> {
        self.get_info_call(None, GetInfoRequest {}).await
    }
    async fn get_info_call(&self, connection: Option<&DynRpcConnection>, request: GetInfoRequest) -> RpcResult<GetInfoResponse>;

    ///
    async fn estimate_network_hashes_per_second(&self, window_size: u32, start_hash: Option<RpcHash>) -> RpcResult<u64> {
        Ok(self
            .estimate_network_hashes_per_second_call(None, EstimateNetworkHashesPerSecondRequest::new(window_size, start_hash))
            .await?
            .network_hashes_per_second)
    }
    async fn estimate_network_hashes_per_second_call(
        &self,
        connection: Option<&DynRpcConnection>,
        request: EstimateNetworkHashesPerSecondRequest,
    ) -> RpcResult<EstimateNetworkHashesPerSecondResponse>;

    ///
    async fn get_mempool_entries_by_addresses(
        &self,
        addresses: Vec<RpcAddress>,
        include_orphan_pool: bool,
        filter_transaction_pool: bool,
    ) -> RpcResult<Vec<RpcMempoolEntryByAddress>> {
        Ok(self
            .get_mempool_entries_by_addresses_call(
                None,
                GetMempoolEntriesByAddressesRequest::new(addresses, include_orphan_pool, filter_transaction_pool),
            )
            .await?
            .entries)
    }
    async fn get_mempool_entries_by_addresses_call(
        &self,
        connection: Option<&DynRpcConnection>,
        request: GetMempoolEntriesByAddressesRequest,
    ) -> RpcResult<GetMempoolEntriesByAddressesResponse>;

    ///
    async fn get_coin_supply(&self) -> RpcResult<GetCoinSupplyResponse> {
        self.get_coin_supply_call(None, GetCoinSupplyRequest {}).await
    }
    async fn get_coin_supply_call(
        &self,
        connection: Option<&DynRpcConnection>,
        request: GetCoinSupplyRequest,
    ) -> RpcResult<GetCoinSupplyResponse>;

    async fn get_daa_score_timestamp_estimate(&self, daa_scores: Vec<u64>) -> RpcResult<Vec<u64>> {
        Ok(self.get_daa_score_timestamp_estimate_call(None, GetDaaScoreTimestampEstimateRequest { daa_scores }).await?.timestamps)
    }
    async fn get_daa_score_timestamp_estimate_call(
        &self,
        connection: Option<&DynRpcConnection>,
        request: GetDaaScoreTimestampEstimateRequest,
    ) -> RpcResult<GetDaaScoreTimestampEstimateResponse>;

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Fee estimation API

    async fn get_fee_estimate(&self) -> RpcResult<RpcFeeEstimate> {
        Ok(self.get_fee_estimate_call(None, GetFeeEstimateRequest {}).await?.estimate)
    }
    async fn get_fee_estimate_call(
        &self,
        connection: Option<&DynRpcConnection>,
        request: GetFeeEstimateRequest,
    ) -> RpcResult<GetFeeEstimateResponse>;

    async fn get_fee_estimate_experimental(&self, verbose: bool) -> RpcResult<GetFeeEstimateExperimentalResponse> {
        self.get_fee_estimate_experimental_call(None, GetFeeEstimateExperimentalRequest { verbose }).await
    }
    async fn get_fee_estimate_experimental_call(
        &self,
        connection: Option<&DynRpcConnection>,
        request: GetFeeEstimateExperimentalRequest,
    ) -> RpcResult<GetFeeEstimateExperimentalResponse>;

    ///
    async fn get_current_block_color(&self, hash: RpcHash) -> RpcResult<GetCurrentBlockColorResponse> {
        Ok(self.get_current_block_color_call(None, GetCurrentBlockColorRequest { hash }).await?)
    }
    async fn get_current_block_color_call(
        &self,
        connection: Option<&DynRpcConnection>,
        request: GetCurrentBlockColorRequest,
    ) -> RpcResult<GetCurrentBlockColorResponse>;

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Notification API

    /// Register a new listener and returns an id identifying it.
    fn register_new_listener(&self, connection: ChannelConnection) -> ListenerId;

    /// Unregister an existing listener.
    ///
    /// Stop all notifications for this listener, unregister the id and its associated connection.
    async fn unregister_listener(&self, id: ListenerId) -> RpcResult<()>;

    /// Start sending notifications of some type to a listener.
    async fn start_notify(&self, id: ListenerId, scope: Scope) -> RpcResult<()>;

    /// Stop sending notifications of some type to a listener.
    async fn stop_notify(&self, id: ListenerId, scope: Scope) -> RpcResult<()>;

    /// Execute a subscription command leading to either start or stop sending notifications
    /// of some type to a listener.
    async fn execute_subscribe_command(&self, id: ListenerId, scope: Scope, command: Command) -> RpcResult<()> {
        match command {
            Command::Start => self.start_notify(id, scope).await,
            Command::Stop => self.stop_notify(id, scope).await,
        }
    }
}

pub type DynRpcService = Arc<dyn RpcApi>;

downcast_sync!(dyn RpcApi);
