use crate::{
    error::{AtomicTokenError, AtomicTokenResult},
    state::{AtomicTokenHealth, AtomicTokenReadView, AtomicTokenSnapshot, AtomicTokenState, ProcessedOp, TokenAsset, TokenEvent},
    IDENT,
};
use async_channel::Receiver;
use blake2b_simd::Params as Blake2bParams;
use borsh::{BorshDeserialize, BorshSerialize};
use cryptix_consensus_core::{
    config::Config,
    hashing::{
        sighash::{calc_schnorr_signature_hash, SigHashReusedValues},
        sighash_type::SIG_HASH_ALL,
    },
    network::NetworkType,
    subnets::{SUBNETWORK_ID_NATIVE, SUBNETWORK_ID_PAYLOAD},
    tx::{
        PopulatedTransaction, ScriptPublicKey, ScriptVec, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput,
        UtxoEntry,
    },
    Hash as BlockHash,
};
use cryptix_consensus_notify::notification::VirtualChainChangedNotification;
use cryptix_consensus_notify::{
    connection::ConsensusChannelConnection, notification::Notification as ConsensusNotification, notifier::ConsensusNotifier,
};
use cryptix_consensusmanager::ConsensusManager;
use cryptix_core::{
    info,
    task::service::{AsyncService, AsyncServiceFuture},
    trace, warn,
};
use cryptix_notify::{connection::ChannelType, listener::ListenerLifespan, scope::VirtualChainChangedScope};
use cryptix_utils::{channel::Channel, triggers::SingleTrigger};
use std::{
    collections::HashMap,
    fs::File,
    io::{ErrorKind, Read, Seek, SeekFrom, Write},
    path::Path,
    path::PathBuf,
    sync::{atomic::AtomicBool, atomic::Ordering, Arc},
};
use tokio::sync::Mutex;

const SERVICE_IDENT: &str = "cryptix-atomic-service";
const TOKEN_PROTOCOL_VERSION: u16 = 4;

const TOKEN_FINALITY_DEPTH_MAINNET: u64 = 86_400;
const TOKEN_FINALITY_DEPTH_TESTNET: u64 = 86_400;
const TOKEN_FINALITY_DEPTH_DEVNET: u64 = 86_400;
const TOKEN_FINALITY_DEPTH_SIMNET: u64 = 432_000;
const TOKEN_REPLAY_OVERLAP_MAINNET: usize = 12_000;
const TOKEN_REPLAY_OVERLAP_TESTNET: usize = 12_000;
const TOKEN_REPLAY_OVERLAP_DEVNET: usize = 12_000;
const TOKEN_REPLAY_OVERLAP_SIMNET: usize = 120_000;
const TOKEN_HISTORY_RETENTION_SLACK_BLOCKS: usize = 2048;
const SNAPSHOT_MANIFEST_DOMAIN: &[u8] = b"CRYPTIX_ATOMIC_SNAPSHOT_MANIFEST_V1";
const SNAPSHOT_ID_DOMAIN: &[u8] = b"CAT_SNAPSHOT_ID_V1";
const SNAPSHOT_CHUNK_SIZE_DEFAULT: usize = 1024 * 1024;
const SNAPSHOT_CHUNK_SIZE_MAX: usize = 4 * 1024 * 1024;
pub const MAX_BOOTSTRAP_SNAPSHOT_FILE_SIZE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub const MAX_BOOTSTRAP_REPLAY_WINDOW_SIZE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const BOOTSTRAP_STORE_MAX_SNAPSHOTS_PER_NETWORK: usize = 16;

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
struct SnapshotManifestV1 {
    schema_version: u16,
    protocol_version: u16,
    network_id: String,
    snapshot_file_name: String,
    snapshot_file_size: u64,
    snapshot_file_hash: [u8; 32],
    snapshot_chunk_size: u32,
    snapshot_chunk_hashes: Vec<[u8; 32]>,
    replay_window_size: u64,
    replay_window_hash: [u8; 32],
    replay_window_chunk_size: u32,
    replay_window_chunk_hashes: Vec<[u8; 32]>,
    at_block_hash: [u8; 32],
    at_daa_score: u64,
    state_hash_at_fp: [u8; 32],
    window_start_block_hash: [u8; 32],
    window_start_parent_block_hash: [u8; 32],
    window_end_block_hash: [u8; 32],
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct ReplayWindowTransferV1 {
    protocol_version: u16,
    network_id: String,
    window_start_block_hash: [u8; 32],
    window_end_block_hash: [u8; 32],
    journals_in_window: Vec<(BlockHash, crate::state::BlockJournal)>,
}

#[derive(Clone, Debug)]
struct SnapshotCatalogEntry {
    snapshot_id_hex: String,
    snapshot_path: PathBuf,
    manifest: SnapshotManifestV1,
    manifest_bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ScBootstrapSource {
    pub snapshot_id: String,
    pub protocol_version: u16,
    pub network_id: String,
    pub node_identity: [u8; 32],
    pub at_block_hash: BlockHash,
    pub at_daa_score: u64,
    pub state_hash_at_fp: [u8; 32],
    pub window_start_block_hash: BlockHash,
    pub window_end_block_hash: BlockHash,
}

#[derive(Clone, Debug)]
pub struct ScSnapshotChunk {
    pub snapshot_id: String,
    pub chunk_index: u32,
    pub total_chunks: u32,
    pub file_size: u64,
    pub chunk_data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ScSnapshotManifestSignature {
    pub signer_pubkey: [u8; 32],
    pub signature: [u8; 64],
}

#[derive(Clone, Debug)]
pub struct ScSnapshotManifestPayload {
    pub snapshot_id: String,
    pub manifest_bytes: Vec<u8>,
    pub signatures: Vec<ScSnapshotManifestSignature>,
}

struct AtomicTokenProcessor {
    consensus_manager: Arc<ConsensusManager>,
    max_retained_blocks: usize,
    operation_lock: Mutex<()>,
    bootstrap_in_progress: AtomicBool,
    state: Mutex<AtomicTokenState>,
    state_path: PathBuf,
}

impl AtomicTokenProcessor {
    fn new(
        consensus_manager: Arc<ConsensusManager>,
        max_retained_blocks: usize,
        state: AtomicTokenState,
        state_path: PathBuf,
    ) -> Self {
        Self {
            consensus_manager,
            max_retained_blocks,
            operation_lock: Default::default(),
            bootstrap_in_progress: AtomicBool::new(false),
            state: Mutex::new(state),
            state_path,
        }
    }

    fn set_bootstrap_in_progress(&self, value: bool) {
        self.bootstrap_in_progress.store(value, Ordering::SeqCst);
    }

    async fn collect_auth_inputs_for_added_blocks(
        &self,
        added_chain_block_hashes: &[BlockHash],
    ) -> AtomicTokenResult<HashMap<TransactionOutpoint, UtxoEntry>> {
        let consensus = self.consensus_manager.consensus();
        let session = consensus.session().await;
        let mut auth_inputs = HashMap::new();
        for block_hash in added_chain_block_hashes.iter().copied() {
            let utxo_diff = session.async_get_block_utxo_diff(block_hash).await?;
            auth_inputs.extend(utxo_diff.remove.iter().map(|(outpoint, entry)| (*outpoint, entry.clone())));
        }
        Ok(auth_inputs)
    }

    async fn process(&self, notification: ConsensusNotification) -> AtomicTokenResult<()> {
        let _operation_guard = self.operation_lock.lock().await;
        match notification {
            ConsensusNotification::UtxosChanged(_) => Ok(()),
            ConsensusNotification::VirtualChainChanged(msg) => {
                let auth_inputs_snapshot = match self.collect_auth_inputs_for_added_blocks(msg.added_chain_block_hashes.as_ref()).await
                {
                    Ok(value) => value,
                    Err(err) => {
                        self.mark_degraded_best_effort(&format!("failed collecting auth inputs for virtual chain update: {err}"))
                            .await;
                        return Err(err);
                    }
                };

                let mut state = self.state.lock().await;
                if let Err(err) = state.apply_virtual_chain_change(&msg, &auth_inputs_snapshot, &self.consensus_manager).await {
                    if !state.degraded {
                        warn!("[{IDENT}] marking Cryptix Atomic degraded after processing error: {err}");
                    }
                    state.mark_degraded();
                    let _ = persist_state_to_path(&self.state_path, &state);
                    return Err(err);
                }
                state.prune_history(self.max_retained_blocks);
                if let Err(err) = persist_state_to_path(&self.state_path, &state) {
                    if !state.degraded {
                        warn!("[{IDENT}] marking Cryptix Atomic degraded after persistence error: {err}");
                    }
                    state.mark_degraded();
                    let _ = persist_state_to_path(&self.state_path, &state);
                    return Err(err);
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    async fn state_hash(&self) -> [u8; 32] {
        self.state.lock().await.get_state_hash()
    }

    async fn health(&self) -> AtomicTokenHealth {
        let bootstrap_in_progress = self.bootstrap_in_progress.load(Ordering::SeqCst);
        let state = self.state.lock().await;
        let mut health = state.get_health();
        health.bootstrap_in_progress = bootstrap_in_progress;
        health.runtime_state = state.runtime_state(bootstrap_in_progress);
        health
    }

    async fn balance(&self, asset_id: [u8; 32], owner_id: [u8; 32]) -> u128 {
        self.state.lock().await.get_balance(asset_id, owner_id)
    }

    async fn nonce(&self, owner_id: [u8; 32]) -> u64 {
        self.state.lock().await.get_nonce(owner_id)
    }

    async fn asset(&self, asset_id: [u8; 32]) -> Option<TokenAsset> {
        self.state.lock().await.get_asset(asset_id)
    }

    async fn op_status(&self, txid: BlockHash) -> Option<ProcessedOp> {
        self.state.lock().await.get_op_status(txid)
    }

    async fn events_since(&self, after_sequence: u64, limit: usize) -> Vec<TokenEvent> {
        self.state.lock().await.get_events_since(after_sequence, limit)
    }

    async fn events_since_capped(&self, after_sequence: u64, limit: usize, max_sequence: u64) -> Vec<TokenEvent> {
        self.state.lock().await.get_events_since_capped(after_sequence, limit, max_sequence)
    }

    async fn read_view(
        &self,
        requested_at_block_hash: Option<BlockHash>,
        fallback_block_hash: BlockHash,
    ) -> Option<AtomicTokenReadView> {
        let bootstrap_in_progress = self.bootstrap_in_progress.load(Ordering::SeqCst);
        let state = self.state.lock().await;
        let runtime_state = state.runtime_state(bootstrap_in_progress);
        let mut view = match requested_at_block_hash {
            Some(at_block_hash) => state.materialize_view_at_block(at_block_hash),
            None => Some(state.materialize_latest_view(fallback_block_hash)),
        };
        if let Some(view) = view.as_mut() {
            view.runtime_state = runtime_state;
        }
        view
    }

    async fn persist_state(&self) -> AtomicTokenResult<()> {
        let state = self.state.lock().await;
        persist_state_to_path(&self.state_path, &state)
    }

    async fn mark_degraded_best_effort(&self, reason: &str) {
        let mut state = self.state.lock().await;
        if !state.degraded {
            warn!("[{IDENT}] marking Cryptix Atomic degraded: {reason}");
        }
        state.mark_degraded();
        if let Err(err) = persist_state_to_path(&self.state_path, &state) {
            warn!("[{IDENT}] failed persisting degraded Cryptix Atomic state: {err}");
        }
    }
}

pub struct AtomicTokenService {
    recv_channel: Receiver<ConsensusNotification>,
    processor: Arc<AtomicTokenProcessor>,
    shutdown: SingleTrigger,
    expected_finality_depth: u64,
    replay_overlap: usize,
    max_retained_blocks: usize,
    genesis_hash: BlockHash,
    unsafe_skip_snapshot_finality_check: bool,
    atomic_data_dir: PathBuf,
    snapshot_store_dir: PathBuf,
    snapshot_refresh_lock: Mutex<()>,
    network_id: String,
    protocol_version: u16,
    node_identity: [u8; 32],
}

impl AtomicTokenService {
    pub fn new(
        consensus_notifier: &Arc<ConsensusNotifier>,
        consensus_manager: Arc<ConsensusManager>,
        config: Arc<Config>,
        atomic_data_dir: PathBuf,
        node_identity: [u8; 32],
    ) -> AtomicTokenResult<Self> {
        validate_startup_constraints(config.as_ref())?;
        validate_cryptographic_binding_self_test()?;
        let expected_finality_depth = token_finality_depth_for_network_type(config.params.net.network_type());
        let replay_overlap = token_replay_overlap_for_network_type(config.params.net.network_type());
        let max_retained_blocks = max_retained_blocks(expected_finality_depth, replay_overlap);

        let network_id = config.params.network_name();
        std::fs::create_dir_all(&atomic_data_dir)
            .map_err(|e| AtomicTokenError::Processing(format!("failed to create Atomic data directory: {e}")))?;
        let snapshot_store_dir = atomic_data_dir.join("bootstrap");
        std::fs::create_dir_all(&snapshot_store_dir)
            .map_err(|e| AtomicTokenError::Processing(format!("failed to create Atomic bootstrap directory: {e}")))?;
        let state_path = atomic_data_dir.join("state.bin");
        let mut state = load_state_from_path(&state_path, TOKEN_PROTOCOL_VERSION, &network_id)?
            .unwrap_or_else(|| AtomicTokenState::new(TOKEN_PROTOCOL_VERSION, network_id.clone()));
        state.set_payload_hf_activation_daa_score(config.params.payload_hf_activation_daa_score);
        state.rebuild_runtime_caches();

        let consensus_notify_channel = Channel::<ConsensusNotification>::default();
        let listener_id = consensus_notifier.register_new_listener(
            ConsensusChannelConnection::new(SERVICE_IDENT, consensus_notify_channel.sender(), ChannelType::Closable),
            ListenerLifespan::Static(Default::default()),
        );

        consensus_notifier
            .try_start_notify(listener_id, VirtualChainChangedScope::new(true).into())
            .map_err(|e| AtomicTokenError::Processing(format!("failed to subscribe to virtual chain changed notifications: {e}")))?;

        info!(
            "[{IDENT}] Cryptix Atomic enabled on `{}` (protocol {}, finality depth {})",
            network_id, TOKEN_PROTOCOL_VERSION, config.params.finality_depth
        );
        if config.atomic_unsafe_skip_snapshot_finality_check {
            warn!("[{IDENT}] UNSAFE: snapshot finality depth sanity check is disabled by configuration");
        }
        Ok(Self {
            recv_channel: consensus_notify_channel.receiver(),
            processor: Arc::new(AtomicTokenProcessor::new(consensus_manager, max_retained_blocks, state, state_path)),
            shutdown: Default::default(),
            expected_finality_depth,
            replay_overlap,
            max_retained_blocks,
            genesis_hash: config.params.genesis.hash,
            unsafe_skip_snapshot_finality_check: config.atomic_unsafe_skip_snapshot_finality_check,
            atomic_data_dir,
            snapshot_store_dir,
            snapshot_refresh_lock: Default::default(),
            network_id,
            protocol_version: TOKEN_PROTOCOL_VERSION,
            node_identity,
        })
    }

    pub fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub fn network_id(&self) -> &str {
        &self.network_id
    }

    pub fn atomic_data_dir(&self) -> &Path {
        &self.atomic_data_dir
    }

    pub async fn get_state_hash(&self) -> [u8; 32] {
        self.processor.state_hash().await
    }

    pub async fn get_health(&self) -> AtomicTokenHealth {
        self.processor.health().await
    }

    pub async fn get_state_hash_at_block(&self, at_block_hash: BlockHash) -> Option<[u8; 32]> {
        self.processor.state.lock().await.get_state_hash_at_block(at_block_hash)
    }

    pub async fn mark_degraded_and_persist(&self, reason: &str) -> AtomicTokenResult<()> {
        let _operation_guard = self.processor.operation_lock.lock().await;
        let mut state = self.processor.state.lock().await;
        if !state.degraded {
            warn!("[{IDENT}] marking Cryptix Atomic state degraded: {reason}");
        }
        state.mark_degraded();
        persist_state_to_path(&self.processor.state_path, &state)
    }

    pub async fn get_balance(&self, asset_id: [u8; 32], owner_id: [u8; 32]) -> u128 {
        self.processor.balance(asset_id, owner_id).await
    }

    pub async fn get_nonce(&self, owner_id: [u8; 32]) -> u64 {
        self.processor.nonce(owner_id).await
    }

    pub async fn get_asset(&self, asset_id: [u8; 32]) -> Option<TokenAsset> {
        self.processor.asset(asset_id).await
    }

    pub async fn get_op_status(&self, txid: BlockHash) -> Option<ProcessedOp> {
        self.processor.op_status(txid).await
    }

    pub async fn get_events_since(&self, after_sequence: u64, limit: usize) -> Vec<TokenEvent> {
        self.processor.events_since(after_sequence, limit).await
    }

    pub async fn get_events_since_capped(&self, after_sequence: u64, limit: usize, max_sequence: u64) -> Vec<TokenEvent> {
        self.processor.events_since_capped(after_sequence, limit, max_sequence).await
    }

    pub async fn get_read_view(&self, requested_at_block_hash: Option<BlockHash>) -> Option<AtomicTokenReadView> {
        self.processor.read_view(requested_at_block_hash, self.genesis_hash).await
    }

    async fn revalidate_loaded_state(&self) -> AtomicTokenResult<bool> {
        let _operation_guard = self.processor.operation_lock.lock().await;

        let loaded_state = {
            let state = self.processor.state.lock().await;
            if !state.has_verified_state() {
                return Ok(false);
            }
            state.clone()
        };

        let first_retained_block_hash = *loaded_state.applied_chain_order.first().ok_or_else(|| {
            AtomicTokenError::Processing("startup state revalidation failed: retained chain is unexpectedly empty".to_string())
        })?;
        let expected_chain = loaded_state.applied_chain_order.clone();
        let expected_hashes = loaded_state.state_hash_by_block.clone();

        let consensus = self.processor.consensus_manager.consensus();
        let session = consensus.session().await;
        let sink = session.async_get_sink().await;
        let first_retained_parent = session.async_get_ghostdag_data(first_retained_block_hash).await?.selected_parent;

        if !session.async_is_chain_ancestor_of(first_retained_parent, sink).await? {
            return Err(AtomicTokenError::Processing(format!(
                "startup state revalidation failed: retained root parent `{first_retained_parent}` is not on the current canonical chain"
            )));
        }

        let replay_chain = session.async_get_virtual_chain_from_block(first_retained_parent, None).await?;
        if !replay_chain.removed.is_empty() {
            return Err(AtomicTokenError::Processing(
                "startup state revalidation failed: expected empty removed chain from retained root parent".to_string(),
            ));
        }
        if replay_chain.added.first().copied() != Some(first_retained_block_hash) {
            return Err(AtomicTokenError::Processing(format!(
                "startup state revalidation failed: canonical replay path does not start at retained root `{first_retained_block_hash}`"
            )));
        }

        let acceptance_data = session.async_get_blocks_acceptance_data(replay_chain.added.clone(), None).await?;
        if acceptance_data.len() != replay_chain.added.len() {
            return Err(AtomicTokenError::Processing(format!(
                "startup state revalidation failed: acceptance-data length mismatch ({} != {})",
                acceptance_data.len(),
                replay_chain.added.len()
            )));
        }
        let auth_inputs = self.processor.collect_auth_inputs_for_added_blocks(&replay_chain.added).await?;

        let mut staged_state = loaded_state;
        staged_state.degraded = false;
        staged_state.live_correct = false;
        staged_state.rollback_snapshot_window_to_parent(first_retained_block_hash)?;

        let replay_notification = VirtualChainChangedNotification::new(
            Arc::new(replay_chain.added.clone()),
            Arc::new(Vec::new()),
            Arc::new(acceptance_data),
        );
        staged_state.apply_virtual_chain_change(&replay_notification, &auth_inputs, &self.processor.consensus_manager).await?;

        let matching_prefix_len =
            expected_chain.iter().zip(replay_chain.added.iter()).take_while(|(expected, actual)| expected == actual).count();
        for block_hash in expected_chain.iter().take(matching_prefix_len).copied() {
            let expected_state_hash = expected_hashes.get(&block_hash).copied().ok_or_else(|| {
                AtomicTokenError::Processing(format!(
                    "startup state revalidation failed: missing persisted state hash for retained block `{block_hash}`"
                ))
            })?;
            let replayed_state_hash = staged_state.get_state_hash_at_block(block_hash).ok_or_else(|| {
                AtomicTokenError::Processing(format!(
                    "startup state revalidation failed: replay did not reproduce retained block `{block_hash}`"
                ))
            })?;
            if replayed_state_hash != expected_state_hash {
                return Err(AtomicTokenError::Processing(format!(
                    "startup state revalidation failed: retained state hash mismatch at block `{block_hash}`"
                )));
            }
        }

        staged_state.prune_history(self.max_retained_blocks);
        staged_state.degraded = false;
        staged_state.live_correct = true;

        let mut state = self.processor.state.lock().await;
        *state = staged_state;
        persist_state_to_path(&self.processor.state_path, &state)?;
        Ok(true)
    }

    async fn ensure_bootstrap_serving_ready(&self) -> AtomicTokenResult<()> {
        if self.processor.bootstrap_in_progress.load(Ordering::SeqCst) {
            return Err(AtomicTokenError::Processing(
                "bootstrap source export unavailable: snapshot bootstrap import is currently in progress".to_string(),
            ));
        }

        let state = self.processor.state.lock().await;
        if state.degraded {
            return Err(AtomicTokenError::Processing(
                "bootstrap source export unavailable: local Atomic state is degraded".to_string(),
            ));
        }
        if !state.has_verified_state() || !state.live_correct {
            return Err(AtomicTokenError::Processing(
                "bootstrap source export unavailable: local Atomic state is not yet revalidated as live-correct".to_string(),
            ));
        }

        Ok(())
    }

    async fn current_snapshot_anchor(&self) -> AtomicTokenResult<(BlockHash, u64)> {
        self.ensure_bootstrap_serving_ready().await?;

        let consensus = self.processor.consensus_manager.consensus();
        let session = consensus.session().await;
        let sink = session.async_get_sink().await;
        let fp = session.async_finality_point().await;
        let sink_header = session.async_get_header(sink).await?;

        if self.unsafe_skip_snapshot_finality_check {
            let state = self.processor.state.lock().await;
            let anchor_hash = *state.applied_chain_order.last().ok_or_else(|| {
                AtomicTokenError::Processing("snapshot export failed: no local Atomic chain order available".to_string())
            })?;
            let anchor_header = session.async_get_header(anchor_hash).await?;
            return Ok((anchor_hash, anchor_header.daa_score));
        }

        let is_ancestor = session.async_is_chain_ancestor_of(fp, sink).await?;
        if !is_ancestor {
            return Err(AtomicTokenError::Processing("snapshot export failed: finality_point is not ancestor of sink".to_string()));
        }

        let fp_header = session.async_get_header(fp).await?;
        if sink_header.blue_score.saturating_sub(fp_header.blue_score) < self.expected_finality_depth {
            return Err(AtomicTokenError::Processing("snapshot export failed: finality depth sanity check failed".to_string()));
        }

        Ok((fp, fp_header.daa_score))
    }

    fn prune_bootstrap_snapshot_store(&self) -> AtomicTokenResult<()> {
        prune_snapshot_catalog_entries(
            &self.snapshot_store_dir,
            self.protocol_version,
            &self.network_id,
            BOOTSTRAP_STORE_MAX_SNAPSHOTS_PER_NETWORK,
        )
    }

    async fn ensure_current_bootstrap_snapshot(&self) -> AtomicTokenResult<()> {
        let _refresh_guard = self.snapshot_refresh_lock.lock().await;
        let (anchor_hash, _anchor_daa_score) = self.current_snapshot_anchor().await?;
        let anchor_hash_bytes = hash_to_array(anchor_hash);
        let already_present = list_snapshot_catalog(&self.snapshot_store_dir)?.into_iter().any(|entry| {
            entry.manifest.protocol_version == self.protocol_version
                && entry.manifest.network_id == self.network_id
                && entry.manifest.at_block_hash == anchor_hash_bytes
        });
        if already_present {
            let _ = self.prune_bootstrap_snapshot_store();
            return Ok(());
        }

        let snapshot_path = self.snapshot_store_dir.join(format!("atomic-snapshot-{}.bin", anchor_hash));
        self.export_snapshot_to_file(snapshot_path).await?;
        let _ = self.prune_bootstrap_snapshot_store();
        Ok(())
    }

    pub async fn get_sc_bootstrap_sources(&self) -> AtomicTokenResult<Vec<ScBootstrapSource>> {
        self.ensure_bootstrap_serving_ready().await?;

        if let Err(err) = self.ensure_current_bootstrap_snapshot().await {
            trace!("[{IDENT}] skipping bootstrap snapshot refresh: {err}");
        }

        let mut sources = list_snapshot_catalog(&self.snapshot_store_dir)?
            .into_iter()
            .filter(|entry| entry.manifest.protocol_version == self.protocol_version && entry.manifest.network_id == self.network_id)
            .map(|entry| ScBootstrapSource {
                snapshot_id: entry.snapshot_id_hex,
                protocol_version: entry.manifest.protocol_version,
                network_id: entry.manifest.network_id,
                node_identity: self.node_identity,
                at_block_hash: BlockHash::from_bytes(entry.manifest.at_block_hash),
                at_daa_score: entry.manifest.at_daa_score,
                state_hash_at_fp: entry.manifest.state_hash_at_fp,
                window_start_block_hash: BlockHash::from_bytes(entry.manifest.window_start_block_hash),
                window_end_block_hash: BlockHash::from_bytes(entry.manifest.window_end_block_hash),
            })
            .collect::<Vec<_>>();
        sources.sort_by(|a, b| b.at_daa_score.cmp(&a.at_daa_score).then(b.at_block_hash.as_bytes().cmp(&a.at_block_hash.as_bytes())));
        Ok(sources)
    }

    pub async fn get_sc_snapshot_head(&self) -> AtomicTokenResult<Option<ScBootstrapSource>> {
        Ok(self.get_sc_bootstrap_sources().await?.into_iter().next())
    }

    pub async fn get_sc_snapshot_manifest(&self, snapshot_id: &str) -> AtomicTokenResult<ScSnapshotManifestPayload> {
        self.ensure_bootstrap_serving_ready().await?;

        let entry = resolve_snapshot_catalog_entry(&self.snapshot_store_dir, snapshot_id, self.protocol_version, &self.network_id)?;
        Ok(ScSnapshotManifestPayload {
            snapshot_id: entry.snapshot_id_hex,
            manifest_bytes: entry.manifest_bytes,
            signatures: Vec::new(),
        })
    }

    pub async fn get_sc_snapshot_chunk(
        &self,
        snapshot_id: &str,
        chunk_index: u32,
        chunk_size: Option<u32>,
    ) -> AtomicTokenResult<ScSnapshotChunk> {
        self.ensure_bootstrap_serving_ready().await?;

        let entry = resolve_snapshot_catalog_entry(&self.snapshot_store_dir, snapshot_id, self.protocol_version, &self.network_id)?;
        if let Some(requested_chunk_size) = chunk_size {
            if requested_chunk_size != entry.manifest.snapshot_chunk_size {
                return Err(AtomicTokenError::Processing(format!(
                    "requested chunk_size `{requested_chunk_size}` does not match manifest snapshot_chunk_size `{}`",
                    entry.manifest.snapshot_chunk_size
                )));
            }
        }
        let total_chunks = total_chunks_for_file(entry.manifest.snapshot_file_size, entry.manifest.snapshot_chunk_size)?;
        if total_chunks == 0 || chunk_index >= total_chunks {
            return Err(AtomicTokenError::Processing(format!(
                "chunk index `{chunk_index}` out of range (total chunks: {total_chunks})"
            )));
        }
        let chunk_data = read_chunk_from_file(
            &entry.snapshot_path,
            entry.manifest.snapshot_file_size,
            entry.manifest.snapshot_chunk_size,
            chunk_index,
            "snapshot package",
        )?;

        let chunk = ScSnapshotChunk {
            snapshot_id: snapshot_id.to_string(),
            chunk_index,
            total_chunks,
            file_size: entry.manifest.snapshot_file_size,
            chunk_data,
        };
        verify_chunk_hash(&chunk.chunk_data, &entry.manifest.snapshot_chunk_hashes, chunk.chunk_index)?;
        Ok(chunk)
    }

    pub async fn get_sc_replay_window_chunk(
        &self,
        snapshot_id: &str,
        chunk_index: u32,
        chunk_size: Option<u32>,
    ) -> AtomicTokenResult<ScSnapshotChunk> {
        self.ensure_bootstrap_serving_ready().await?;

        let entry = resolve_snapshot_catalog_entry(&self.snapshot_store_dir, snapshot_id, self.protocol_version, &self.network_id)?;
        if let Some(requested_chunk_size) = chunk_size {
            if requested_chunk_size != entry.manifest.replay_window_chunk_size {
                return Err(AtomicTokenError::Processing(format!(
                    "requested chunk_size `{requested_chunk_size}` does not match manifest replay_window_chunk_size `{}`",
                    entry.manifest.replay_window_chunk_size
                )));
            }
        }
        let total_chunks = total_chunks_for_file(entry.manifest.replay_window_size, entry.manifest.replay_window_chunk_size)?;
        if total_chunks == 0 || chunk_index >= total_chunks {
            return Err(AtomicTokenError::Processing(format!(
                "chunk index `{chunk_index}` out of range (total chunks: {total_chunks})"
            )));
        }
        let replay_path = snapshot_replay_path(&entry.snapshot_path);
        let chunk_data = read_chunk_from_file(
            &replay_path,
            entry.manifest.replay_window_size,
            entry.manifest.replay_window_chunk_size,
            chunk_index,
            "snapshot replay window",
        )?;
        let chunk = ScSnapshotChunk {
            snapshot_id: snapshot_id.to_string(),
            chunk_index,
            total_chunks,
            file_size: entry.manifest.replay_window_size,
            chunk_data,
        };
        verify_chunk_hash(&chunk.chunk_data, &entry.manifest.replay_window_chunk_hashes, chunk.chunk_index)?;
        Ok(chunk)
    }

    pub async fn export_snapshot_to_file<P: AsRef<Path>>(&self, path: P) -> AtomicTokenResult<()> {
        let _operation_guard = self.processor.operation_lock.lock().await;
        let (anchor_hash, anchor_daa_score) = self.current_snapshot_anchor().await?;

        let snapshot = {
            let state = self.processor.state.lock().await;
            let anchor_index = state.applied_chain_order.iter().position(|hash| *hash == anchor_hash).ok_or_else(|| {
                AtomicTokenError::Processing(
                    "snapshot export failed: snapshot anchor not found in local Atomic chain order".to_string(),
                )
            })?;
            let start_index = anchor_index.saturating_sub(self.replay_overlap.saturating_sub(1));
            let window_blocks = state.applied_chain_order[start_index..=anchor_index].to_vec();
            let window_start_parent_block_hash =
                if start_index > 0 { state.applied_chain_order[start_index - 1] } else { self.genesis_hash };
            state.export_snapshot(anchor_hash, anchor_daa_score, window_start_parent_block_hash, &window_blocks)?
        };

        let bytes = bincode::serialize(&snapshot).map_err(|e| AtomicTokenError::Processing(format!("snapshot encode failed: {e}")))?;
        let replay_window_bytes = encode_replay_window_transfer(&snapshot)?;
        validate_snapshot_blob_size_limits(bytes.len() as u64, replay_window_bytes.len() as u64, "snapshot export")?;
        std::fs::write(path.as_ref(), &bytes).map_err(|e| AtomicTokenError::Processing(format!("snapshot write failed: {e}")))?;
        std::fs::write(snapshot_replay_path(path.as_ref()), &replay_window_bytes)
            .map_err(|e| AtomicTokenError::Processing(format!("snapshot replay write failed: {e}")))?;

        let manifest = build_snapshot_manifest(path.as_ref(), &bytes, &replay_window_bytes, &snapshot)?;
        let manifest_bytes =
            borsh::to_vec(&manifest).map_err(|e| AtomicTokenError::Processing(format!("snapshot manifest encode failed: {e}")))?;
        std::fs::write(snapshot_manifest_path(path.as_ref()), manifest_bytes)
            .map_err(|e| AtomicTokenError::Processing(format!("snapshot manifest write failed: {e}")))?;

        // Keep a bootstrap-store copy so peers can serve this snapshot via getSc* APIs.
        let store_snapshot_path = self.snapshot_store_dir.join(&manifest.snapshot_file_name);
        if store_snapshot_path != path.as_ref() {
            std::fs::write(&store_snapshot_path, &bytes)
                .map_err(|e| AtomicTokenError::Processing(format!("snapshot store write failed: {e}")))?;
            std::fs::write(snapshot_replay_path(&store_snapshot_path), &replay_window_bytes)
                .map_err(|e| AtomicTokenError::Processing(format!("snapshot store replay write failed: {e}")))?;
            let store_manifest = build_snapshot_manifest(&store_snapshot_path, &bytes, &replay_window_bytes, &snapshot)?;
            let store_manifest_bytes = borsh::to_vec(&store_manifest)
                .map_err(|e| AtomicTokenError::Processing(format!("snapshot store manifest encode failed: {e}")))?;
            std::fs::write(snapshot_manifest_path(&store_snapshot_path), store_manifest_bytes)
                .map_err(|e| AtomicTokenError::Processing(format!("snapshot store manifest write failed: {e}")))?;
        }
        let _ = self.prune_bootstrap_snapshot_store();
        Ok(())
    }

    pub async fn import_snapshot_from_file<P: AsRef<Path>>(&self, path: P) -> AtomicTokenResult<()> {
        let _operation_guard = self.processor.operation_lock.lock().await;
        self.processor.set_bootstrap_in_progress(true);
        let import_result: AtomicTokenResult<()> = async {
            let bytes =
                std::fs::read(path.as_ref()).map_err(|e| AtomicTokenError::Processing(format!("snapshot read failed: {e}")))?;
            validate_snapshot_manifest(path.as_ref(), &bytes, self.protocol_version, &self.network_id)?;
            let snapshot: AtomicTokenSnapshot =
                bincode::deserialize(&bytes).map_err(|e| AtomicTokenError::Processing(format!("snapshot decode failed: {e}")))?;

            let consensus = self.processor.consensus_manager.consensus();
            let session = consensus.session().await;
            let sink = session.async_get_sink().await;
            let fp = session.async_finality_point().await;
            let is_ancestor = session.async_is_chain_ancestor_of(snapshot.at_block_hash, sink).await?;
            if !is_ancestor {
                return Err(AtomicTokenError::Processing(
                    "snapshot import failed: snapshot at_block_hash is not ancestor of current sink".to_string(),
                ));
            }
            let sink_header = session.async_get_header(sink).await?;
            if !self.unsafe_skip_snapshot_finality_check {
                let finalized_by_current_fp = session.async_is_chain_ancestor_of(snapshot.at_block_hash, fp).await?;
                if !finalized_by_current_fp {
                    return Err(AtomicTokenError::Processing(format!(
                        "snapshot import failed: at_block_hash `{}` is not finalized by current finality point `{}`",
                        snapshot.at_block_hash, fp
                    )));
                }
                let fp_header = session.async_get_header(fp).await?;
                if sink_header.blue_score.saturating_sub(fp_header.blue_score) < self.expected_finality_depth {
                    return Err(AtomicTokenError::Processing(
                        "snapshot import failed: finality depth sanity check failed".to_string(),
                    ));
                }
            }

            let replay_chain = session.async_get_virtual_chain_from_block(snapshot.window_start_parent_block_hash, None).await?;
            if !replay_chain.removed.is_empty() {
                return Err(AtomicTokenError::Processing(
                    "snapshot import failed: expected empty removed chain for replay path".to_string(),
                ));
            }

            if replay_chain.added.first().copied().map(|first| first != snapshot.window_start_block_hash).unwrap_or(true) {
                return Err(AtomicTokenError::Processing(
                    "snapshot import failed: replay path does not start with snapshot window_start_block_hash".to_string(),
                ));
            }

            let acceptance_data = session.async_get_blocks_acceptance_data(replay_chain.added.clone(), None).await?;
            if acceptance_data.len() != replay_chain.added.len() {
                return Err(AtomicTokenError::Processing(format!(
                    "snapshot import failed: acceptance data count mismatch ({} != {})",
                    acceptance_data.len(),
                    replay_chain.added.len()
                )));
            }

            // Stage snapshot import and deterministic replay off-line, then swap into live state only if fully verified.
            let mut staged_state = { self.processor.state.lock().await.clone() };
            staged_state.import_snapshot(snapshot.clone())?;
            staged_state.rollback_snapshot_window_to_parent(snapshot.window_start_block_hash)?;
            if let Some(expected_hash) = snapshot.state_hash_at_window_start_parent {
                let current_hash = staged_state.compute_state_hash();
                if current_hash != expected_hash {
                    return Err(AtomicTokenError::Processing(
                        "snapshot import failed: state hash mismatch at window_start parent".to_string(),
                    ));
                }
            }

            for (accepting_block_hash, acceptance) in replay_chain.added.into_iter().zip(acceptance_data.into_iter()) {
                let utxo_diff = session.async_get_block_utxo_diff(accepting_block_hash).await?;
                let auth_inputs: HashMap<TransactionOutpoint, UtxoEntry> =
                    utxo_diff.remove.iter().map(|(outpoint, entry)| (*outpoint, entry.clone())).collect();
                let replay_notification = VirtualChainChangedNotification::new(
                    Arc::new(vec![accepting_block_hash]),
                    Arc::new(Vec::new()),
                    Arc::new(vec![acceptance]),
                );

                if let Err(err) = staged_state
                    .apply_virtual_chain_change(&replay_notification, &auth_inputs, &self.processor.consensus_manager)
                    .await
                {
                    return Err(AtomicTokenError::Processing(format!(
                        "snapshot import replay failed for block `{accepting_block_hash}`: {err}"
                    )));
                }

                if accepting_block_hash == snapshot.at_block_hash {
                    let current_hash = staged_state.compute_state_hash();
                    if current_hash != snapshot.state_hash_at_fp {
                        return Err(AtomicTokenError::Processing(
                            "snapshot import failed: state hash mismatch at snapshot finality point".to_string(),
                        ));
                    }
                }
            }

            staged_state.prune_history(self.max_retained_blocks);
            staged_state.live_correct = !staged_state.degraded;
            {
                let mut live_state = self.processor.state.lock().await;
                *live_state = staged_state;
            }
            self.processor.persist_state().await?;
            Ok(())
        }
        .await;
        self.processor.set_bootstrap_in_progress(false);

        if let Err(err) = import_result {
            let mut state = self.processor.state.lock().await;
            state.mark_degraded();
            let _ = persist_state_to_path(&self.processor.state_path, &state);
            return Err(err);
        }
        Ok(())
    }
}

impl AsyncService for AtomicTokenService {
    fn ident(self: Arc<Self>) -> &'static str {
        SERVICE_IDENT
    }

    fn start(self: Arc<Self>) -> AsyncServiceFuture {
        trace!("{} starting", SERVICE_IDENT);
        let shutdown_signal = self.shutdown.listener.clone();
        Box::pin(async move {
            match self.revalidate_loaded_state().await {
                Ok(true) => info!("[{IDENT}] Cryptix Atomic startup state revalidation completed successfully"),
                Ok(false) => {}
                Err(err) => {
                    warn!("[{IDENT}] Cryptix Atomic startup state revalidation failed: {err}");
                    self.processor.mark_degraded_best_effort(&format!("startup state revalidation failed: {err}")).await;
                }
            }

            loop {
                tokio::select! {
                    _ = shutdown_signal.clone() => {
                        break;
                    }
                    notification = self.recv_channel.recv() => {
                        match notification {
                            Ok(notification) => {
                                if let Err(err) = self.processor.process(notification).await {
                                    warn!("[{IDENT}] Cryptix Atomic processor error: {err}");
                                }
                            }
                            Err(_) => {
                                break;
                            }
                        }
                    }
                }
            }
            Ok(())
        })
    }

    fn signal_exit(self: Arc<Self>) {
        trace!("sending an exit signal to {}", SERVICE_IDENT);
        self.shutdown.trigger.trigger();
    }

    fn stop(self: Arc<Self>) -> AsyncServiceFuture {
        Box::pin(async move {
            trace!("{} stopped", SERVICE_IDENT);
            Ok(())
        })
    }
}

fn snapshot_manifest_path(snapshot_path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.manifest", snapshot_path.display()))
}

fn snapshot_replay_path(snapshot_path: &Path) -> PathBuf {
    snapshot_path.with_extension("replay.bin")
}

fn hash_snapshot_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bParams::new().hash_length(32).to_state();
    hasher.update(SNAPSHOT_MANIFEST_DOMAIN);
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_bytes());
    out
}

fn hash_chunk_bytes(bytes: &[u8]) -> [u8; 32] {
    let digest = Blake2bParams::new().hash_length(32).hash(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_bytes());
    out
}

fn chunk_hashes(bytes: &[u8], chunk_size: usize) -> Vec<[u8; 32]> {
    if bytes.is_empty() {
        return Vec::new();
    }

    let mut hashes = Vec::with_capacity((bytes.len() + chunk_size - 1) / chunk_size);
    let mut start = 0usize;
    while start < bytes.len() {
        let end = usize::min(start + chunk_size, bytes.len());
        hashes.push(hash_chunk_bytes(&bytes[start..end]));
        start = end;
    }
    hashes
}

fn verify_chunk_hash(chunk_data: &[u8], expected_hashes: &[[u8; 32]], chunk_index: u32) -> AtomicTokenResult<()> {
    let idx = chunk_index as usize;
    let expected = expected_hashes
        .get(idx)
        .ok_or_else(|| AtomicTokenError::Processing(format!("chunk index `{chunk_index}` missing from manifest chunk hash list")))?;
    let actual = hash_chunk_bytes(chunk_data);
    if &actual != expected {
        return Err(AtomicTokenError::Processing(format!("chunk hash mismatch at index `{chunk_index}`")));
    }
    Ok(())
}

fn encode_replay_window_transfer(snapshot: &AtomicTokenSnapshot) -> AtomicTokenResult<Vec<u8>> {
    bincode::serialize(&ReplayWindowTransferV1 {
        protocol_version: snapshot.protocol_version,
        network_id: snapshot.network_id.clone(),
        window_start_block_hash: hash_to_array(snapshot.window_start_block_hash),
        window_end_block_hash: hash_to_array(snapshot.window_end_block_hash),
        journals_in_window: snapshot.journals_in_window.clone(),
    })
    .map_err(|e| AtomicTokenError::Processing(format!("failed encoding replay window transfer: {e}")))
}

fn validate_snapshot_blob_size_limits(snapshot_size: u64, replay_size: u64, context: &str) -> AtomicTokenResult<()> {
    if snapshot_size > MAX_BOOTSTRAP_SNAPSHOT_FILE_SIZE_BYTES {
        return Err(AtomicTokenError::Processing(format!(
            "{context} failed: snapshot size `{snapshot_size}` exceeds max `{MAX_BOOTSTRAP_SNAPSHOT_FILE_SIZE_BYTES}`"
        )));
    }
    if replay_size > MAX_BOOTSTRAP_REPLAY_WINDOW_SIZE_BYTES {
        return Err(AtomicTokenError::Processing(format!(
            "{context} failed: replay window size `{replay_size}` exceeds max `{MAX_BOOTSTRAP_REPLAY_WINDOW_SIZE_BYTES}`"
        )));
    }
    Ok(())
}

fn read_chunk_from_file(path: &Path, file_size: u64, chunk_size: u32, chunk_index: u32, label: &str) -> AtomicTokenResult<Vec<u8>> {
    let chunk_size = chunk_size as u64;
    let start = (chunk_index as u64)
        .checked_mul(chunk_size)
        .ok_or_else(|| AtomicTokenError::Processing(format!("chunk offset overflow while reading {label}")))?;
    let end = std::cmp::min(start.saturating_add(chunk_size), file_size);
    let read_len = usize::try_from(end.saturating_sub(start))
        .map_err(|_| AtomicTokenError::Processing(format!("chunk length does not fit in usize while reading {label}")))?;

    let mut file = File::open(path)
        .map_err(|e| AtomicTokenError::Processing(format!("failed opening {label} bytes from `{}`: {e}", path.display())))?;
    file.seek(SeekFrom::Start(start))
        .map_err(|e| AtomicTokenError::Processing(format!("failed seeking {label} bytes in `{}`: {e}", path.display())))?;
    let mut chunk_data = vec![0u8; read_len];
    file.read_exact(&mut chunk_data)
        .map_err(|e| AtomicTokenError::Processing(format!("failed reading {label} chunk bytes from `{}`: {e}", path.display())))?;
    Ok(chunk_data)
}

fn hash_to_array(hash: BlockHash) -> [u8; 32] {
    hash.as_bytes()
}

fn build_snapshot_manifest(
    path: &Path,
    snapshot_bytes: &[u8],
    replay_window_bytes: &[u8],
    snapshot: &AtomicTokenSnapshot,
) -> AtomicTokenResult<SnapshotManifestV1> {
    let snapshot_file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| AtomicTokenError::Processing("snapshot export failed: invalid snapshot file name".to_string()))?
        .to_string();
    let snapshot_chunk_size = SNAPSHOT_CHUNK_SIZE_DEFAULT as u32;
    let replay_window_chunk_size = SNAPSHOT_CHUNK_SIZE_DEFAULT as u32;
    let snapshot_file_size = snapshot_bytes.len() as u64;
    let replay_window_size = replay_window_bytes.len() as u64;
    validate_snapshot_blob_size_limits(snapshot_file_size, replay_window_size, "snapshot export")?;
    Ok(SnapshotManifestV1 {
        schema_version: snapshot.schema_version,
        protocol_version: snapshot.protocol_version,
        network_id: snapshot.network_id.clone(),
        snapshot_file_name,
        snapshot_file_size,
        snapshot_file_hash: hash_snapshot_bytes(snapshot_bytes),
        snapshot_chunk_size,
        snapshot_chunk_hashes: chunk_hashes(snapshot_bytes, snapshot_chunk_size as usize),
        replay_window_size,
        replay_window_hash: hash_snapshot_bytes(replay_window_bytes),
        replay_window_chunk_size,
        replay_window_chunk_hashes: chunk_hashes(replay_window_bytes, replay_window_chunk_size as usize),
        at_block_hash: hash_to_array(snapshot.at_block_hash),
        at_daa_score: snapshot.at_daa_score,
        state_hash_at_fp: snapshot.state_hash_at_fp,
        window_start_block_hash: hash_to_array(snapshot.window_start_block_hash),
        window_start_parent_block_hash: hash_to_array(snapshot.window_start_parent_block_hash),
        window_end_block_hash: hash_to_array(snapshot.window_end_block_hash),
    })
}

fn validate_snapshot_manifest(
    path: &Path,
    snapshot_bytes: &[u8],
    expected_protocol_version: u16,
    expected_network_id: &str,
) -> AtomicTokenResult<()> {
    let manifest_bytes = std::fs::read(snapshot_manifest_path(path))
        .map_err(|e| AtomicTokenError::Processing(format!("snapshot manifest read failed: {e}")))?;
    let manifest = SnapshotManifestV1::try_from_slice(&manifest_bytes)
        .map_err(|e| AtomicTokenError::Processing(format!("snapshot manifest decode failed: {e}")))?;

    let snapshot_file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| AtomicTokenError::Processing("snapshot import failed: invalid snapshot file name".to_string()))?;
    if manifest.snapshot_file_name != snapshot_file_name {
        return Err(AtomicTokenError::Processing("snapshot import failed: manifest snapshot file name mismatch".to_string()));
    }
    if manifest.protocol_version != expected_protocol_version {
        return Err(AtomicTokenError::SnapshotProtocolMismatch {
            expected: expected_protocol_version,
            actual: manifest.protocol_version,
        });
    }
    if manifest.network_id != expected_network_id {
        return Err(AtomicTokenError::SnapshotNetworkMismatch {
            expected: expected_network_id.to_string(),
            actual: manifest.network_id,
        });
    }
    validate_snapshot_blob_size_limits(manifest.snapshot_file_size, manifest.replay_window_size, "snapshot import")?;
    if manifest.snapshot_file_size != snapshot_bytes.len() as u64 {
        return Err(AtomicTokenError::Processing("snapshot import failed: manifest snapshot size mismatch".to_string()));
    }
    let expected_hash = hash_snapshot_bytes(snapshot_bytes);
    if manifest.snapshot_file_hash != expected_hash {
        return Err(AtomicTokenError::Processing("snapshot import failed: manifest snapshot hash mismatch".to_string()));
    }
    if manifest.snapshot_chunk_size == 0 {
        return Err(AtomicTokenError::Processing(
            "snapshot import failed: manifest snapshot_chunk_size must be greater than zero".to_string(),
        ));
    }
    if manifest.snapshot_chunk_size as usize > SNAPSHOT_CHUNK_SIZE_MAX {
        return Err(AtomicTokenError::Processing(format!(
            "snapshot import failed: manifest snapshot_chunk_size exceeds maximum `{SNAPSHOT_CHUNK_SIZE_MAX}`"
        )));
    }
    let snapshot_chunk_hashes = chunk_hashes(snapshot_bytes, manifest.snapshot_chunk_size as usize);
    if snapshot_chunk_hashes != manifest.snapshot_chunk_hashes {
        return Err(AtomicTokenError::Processing("snapshot import failed: manifest snapshot chunk hashes mismatch".to_string()));
    }

    let snapshot: AtomicTokenSnapshot =
        bincode::deserialize(snapshot_bytes).map_err(|e| AtomicTokenError::Processing(format!("snapshot decode failed: {e}")))?;
    if snapshot.schema_version != manifest.schema_version
        || snapshot.protocol_version != manifest.protocol_version
        || snapshot.network_id != manifest.network_id
        || hash_to_array(snapshot.at_block_hash) != manifest.at_block_hash
        || snapshot.at_daa_score != manifest.at_daa_score
        || snapshot.state_hash_at_fp != manifest.state_hash_at_fp
        || hash_to_array(snapshot.window_start_block_hash) != manifest.window_start_block_hash
        || hash_to_array(snapshot.window_start_parent_block_hash) != manifest.window_start_parent_block_hash
        || hash_to_array(snapshot.window_end_block_hash) != manifest.window_end_block_hash
    {
        return Err(AtomicTokenError::Processing(
            "snapshot import failed: manifest metadata does not match decoded snapshot contents".to_string(),
        ));
    }
    let replay_window_bytes = encode_replay_window_transfer(&snapshot)?;
    if manifest.replay_window_size != replay_window_bytes.len() as u64 {
        return Err(AtomicTokenError::Processing("snapshot import failed: manifest replay window size mismatch".to_string()));
    }
    if manifest.replay_window_hash != hash_snapshot_bytes(&replay_window_bytes) {
        return Err(AtomicTokenError::Processing("snapshot import failed: manifest replay window hash mismatch".to_string()));
    }
    if manifest.replay_window_chunk_size == 0 {
        return Err(AtomicTokenError::Processing(
            "snapshot import failed: manifest replay_window_chunk_size must be greater than zero".to_string(),
        ));
    }
    if manifest.replay_window_chunk_size as usize > SNAPSHOT_CHUNK_SIZE_MAX {
        return Err(AtomicTokenError::Processing(format!(
            "snapshot import failed: manifest replay_window_chunk_size exceeds maximum `{SNAPSHOT_CHUNK_SIZE_MAX}`"
        )));
    }
    let replay_window_chunk_hashes = chunk_hashes(&replay_window_bytes, manifest.replay_window_chunk_size as usize);
    if replay_window_chunk_hashes != manifest.replay_window_chunk_hashes {
        return Err(AtomicTokenError::Processing("snapshot import failed: manifest replay window chunk hashes mismatch".to_string()));
    }
    Ok(())
}

fn load_state_from_path(path: &Path, protocol_version: u16, network_id: &str) -> AtomicTokenResult<Option<AtomicTokenState>> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(path).map_err(|e| AtomicTokenError::Processing(format!("failed reading Atomic state file: {e}")))?;
    let mut state: AtomicTokenState =
        bincode::deserialize(&bytes).map_err(|e| AtomicTokenError::Processing(format!("failed decoding Atomic state file: {e}")))?;
    if state.protocol_version != protocol_version {
        warn!(
            "[{IDENT}] ignoring persisted Atomic state at `{}` due to protocol mismatch (expected {}, got {})",
            path.display(),
            protocol_version,
            state.protocol_version
        );
        return Ok(None);
    }
    if state.network_id != network_id {
        warn!(
            "[{IDENT}] ignoring persisted Atomic state at `{}` due to network mismatch (expected `{}`, got `{}`)",
            path.display(),
            network_id,
            state.network_id
        );
        return Ok(None);
    }
    state.live_correct = false;
    state.rebuild_event_id_index();
    Ok(Some(state))
}

fn persist_state_to_path(path: &Path, state: &AtomicTokenState) -> AtomicTokenResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| AtomicTokenError::Processing("failed persisting Atomic state: state path has no parent".to_string()))?;
    std::fs::create_dir_all(parent)
        .map_err(|e| AtomicTokenError::Processing(format!("failed creating Atomic state parent directory: {e}")))?;
    let bytes = bincode::serialize(state).map_err(|e| AtomicTokenError::Processing(format!("failed encoding Atomic state: {e}")))?;

    let tmp_path = path.with_extension("tmp");
    {
        let mut tmp_file = File::create(&tmp_path)
            .map_err(|e| AtomicTokenError::Processing(format!("failed creating Atomic state temp file: {e}")))?;
        tmp_file.write_all(&bytes).map_err(|e| AtomicTokenError::Processing(format!("failed writing Atomic state temp file: {e}")))?;
        tmp_file.sync_all().map_err(|e| AtomicTokenError::Processing(format!("failed syncing Atomic state temp file: {e}")))?;
    }

    replace_file_cross_platform(&tmp_path, path)?;
    sync_parent_directory(parent);
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn replace_file_cross_platform(source: &Path, target: &Path) -> AtomicTokenResult<()> {
    std::fs::rename(source, target).map_err(|err| AtomicTokenError::Processing(format!("failed replacing Atomic state file: {err}")))
}

#[cfg(target_os = "windows")]
fn replace_file_cross_platform(source: &Path, target: &Path) -> AtomicTokenResult<()> {
    if !target.exists() {
        return std::fs::rename(source, target)
            .map_err(|err| AtomicTokenError::Processing(format!("failed replacing Atomic state file: {err}")));
    }

    const REPLACEFILE_WRITE_THROUGH: u32 = 0x00000002;
    let source_wide = encode_windows_path(source);
    let target_wide = encode_windows_path(target);

    let replaced = unsafe {
        ReplaceFileW(
            target_wide.as_ptr(),
            source_wide.as_ptr(),
            std::ptr::null(),
            REPLACEFILE_WRITE_THROUGH,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if replaced == 0 {
        return Err(AtomicTokenError::Processing(format!("failed replacing Atomic state file: {}", std::io::Error::last_os_error())));
    }

    Ok(())
}

#[cfg(target_os = "windows")]
#[link(name = "Kernel32")]
unsafe extern "system" {
    fn ReplaceFileW(
        lpReplacedFileName: *const u16,
        lpReplacementFileName: *const u16,
        lpBackupFileName: *const u16,
        dwReplaceFlags: u32,
        lpExclude: *mut std::ffi::c_void,
        lpReserved: *mut std::ffi::c_void,
    ) -> i32;
}

#[cfg(target_os = "windows")]
fn encode_windows_path(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(not(target_os = "windows"))]
fn sync_parent_directory(parent: &Path) {
    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }
}

#[cfg(target_os = "windows")]
fn sync_parent_directory(_parent: &Path) {}

fn snapshot_id_from_manifest(manifest_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bParams::new().hash_length(32).to_state();
    hasher.update(SNAPSHOT_ID_DOMAIN);
    hasher.update(manifest_bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_bytes());
    out
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn list_snapshot_catalog(snapshot_store_dir: &Path) -> AtomicTokenResult<Vec<SnapshotCatalogEntry>> {
    if !snapshot_store_dir.exists() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(snapshot_store_dir)
        .map_err(|e| AtomicTokenError::Processing(format!("failed reading snapshot store directory: {e}")))?
    {
        let entry = entry.map_err(|e| AtomicTokenError::Processing(format!("failed reading snapshot store entry: {e}")))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !file_name.ends_with(".manifest") {
            continue;
        }

        let manifest_bytes =
            std::fs::read(&path).map_err(|e| AtomicTokenError::Processing(format!("failed reading snapshot manifest file: {e}")))?;
        let manifest = SnapshotManifestV1::try_from_slice(&manifest_bytes)
            .map_err(|e| AtomicTokenError::Processing(format!("failed decoding snapshot manifest file: {e}")))?;
        if validate_snapshot_blob_size_limits(manifest.snapshot_file_size, manifest.replay_window_size, "snapshot catalog validation")
            .is_err()
        {
            continue;
        }
        if manifest.snapshot_chunk_size == 0 || manifest.snapshot_chunk_size as usize > SNAPSHOT_CHUNK_SIZE_MAX {
            continue;
        }
        if manifest.replay_window_chunk_size == 0 || manifest.replay_window_chunk_size as usize > SNAPSHOT_CHUNK_SIZE_MAX {
            continue;
        }
        let expected_snapshot_chunks = match total_chunks_for_file(manifest.snapshot_file_size, manifest.snapshot_chunk_size) {
            Ok(value) => value as usize,
            Err(_) => continue,
        };
        if expected_snapshot_chunks == 0 || manifest.snapshot_chunk_hashes.len() != expected_snapshot_chunks {
            continue;
        }
        let expected_replay_chunks = match total_chunks_for_file(manifest.replay_window_size, manifest.replay_window_chunk_size) {
            Ok(value) => value as usize,
            Err(_) => continue,
        };
        if manifest.replay_window_chunk_hashes.len() != expected_replay_chunks {
            continue;
        }

        let snapshot_path = path.with_extension("");
        if snapshot_path.file_name().and_then(|name| name.to_str()) != Some(manifest.snapshot_file_name.as_str()) {
            continue;
        }
        let snapshot_meta = match std::fs::metadata(&snapshot_path) {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if !snapshot_meta.is_file() || snapshot_meta.len() != manifest.snapshot_file_size {
            continue;
        }
        let replay_path = snapshot_replay_path(&snapshot_path);
        let replay_meta = match std::fs::metadata(&replay_path) {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if !replay_meta.is_file() || replay_meta.len() != manifest.replay_window_size {
            continue;
        }

        let snapshot_id_hex = to_hex(&snapshot_id_from_manifest(&manifest_bytes));
        entries.push(SnapshotCatalogEntry { snapshot_id_hex, snapshot_path, manifest, manifest_bytes });
    }
    Ok(entries)
}

fn remove_file_if_exists(path: &Path) -> AtomicTokenResult<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(AtomicTokenError::Processing(format!("failed removing `{}`: {err}", path.display()))),
    }
}

fn prune_snapshot_catalog_entries(
    snapshot_store_dir: &Path,
    protocol_version: u16,
    network_id: &str,
    max_entries: usize,
) -> AtomicTokenResult<()> {
    if max_entries == 0 {
        return Ok(());
    }

    let mut entries = list_snapshot_catalog(snapshot_store_dir)?
        .into_iter()
        .filter(|entry| entry.manifest.protocol_version == protocol_version && entry.manifest.network_id == network_id)
        .collect::<Vec<_>>();
    if entries.len() <= max_entries {
        return Ok(());
    }

    entries.sort_by(|a, b| {
        b.manifest
            .at_daa_score
            .cmp(&a.manifest.at_daa_score)
            .then(b.manifest.at_block_hash.cmp(&a.manifest.at_block_hash))
            .then(b.snapshot_id_hex.cmp(&a.snapshot_id_hex))
    });
    for entry in entries.into_iter().skip(max_entries) {
        remove_file_if_exists(&entry.snapshot_path)?;
        remove_file_if_exists(&snapshot_manifest_path(&entry.snapshot_path))?;
        remove_file_if_exists(&snapshot_replay_path(&entry.snapshot_path))?;
    }

    Ok(())
}

fn resolve_snapshot_catalog_entry(
    snapshot_store_dir: &Path,
    snapshot_id: &str,
    expected_protocol_version: u16,
    expected_network_id: &str,
) -> AtomicTokenResult<SnapshotCatalogEntry> {
    let snapshot_id = snapshot_id.to_ascii_lowercase();
    list_snapshot_catalog(snapshot_store_dir)?
        .into_iter()
        .find(|entry| {
            entry.snapshot_id_hex == snapshot_id
                && entry.manifest.protocol_version == expected_protocol_version
                && entry.manifest.network_id == expected_network_id
        })
        .ok_or_else(|| AtomicTokenError::Processing(format!("snapshot `{snapshot_id}` not found in bootstrap store")))
}

fn total_chunks_for_file(file_size: u64, chunk_size: u32) -> AtomicTokenResult<u32> {
    if chunk_size == 0 {
        return Err(AtomicTokenError::Processing("chunk size cannot be zero".to_string()));
    }
    if file_size == 0 {
        return Ok(0);
    }

    let chunk_size = chunk_size as u64;
    let total = file_size
        .checked_add(chunk_size - 1)
        .ok_or_else(|| AtomicTokenError::Processing("chunk count overflow while validating snapshot metadata".to_string()))?
        / chunk_size;
    u32::try_from(total).map_err(|_| AtomicTokenError::Processing("chunk count exceeds u32".to_string()))
}

fn validate_startup_constraints(config: &Config) -> AtomicTokenResult<()> {
    let network_id = config.params.network_name();
    let network_type = config.params.net.network_type();
    let expected_finality_depth = token_finality_depth_for_network_type(config.params.net.network_type());

    let allowed_network_id =
        matches!(network_id.as_str(), "cryptix-mainnet" | "cryptix-testnet" | "cryptix-devnet" | "cryptix-simnet");
    if !allowed_network_id {
        return Err(AtomicTokenError::InvalidNetworkId(network_id));
    }

    if config.atomic_unsafe_skip_snapshot_finality_check && matches!(network_type, NetworkType::Mainnet) {
        return Err(AtomicTokenError::Processing(
            "unsafe snapshot finality override is forbidden on mainnet (remove `atomic_unsafe_skip_snapshot_finality_check`)"
                .to_string(),
        ));
    }

    let actual_finality_depth = config.params.finality_depth;
    if actual_finality_depth != expected_finality_depth {
        return Err(AtomicTokenError::FinalityDepthMismatch { expected: expected_finality_depth, actual: actual_finality_depth });
    }

    Ok(())
}

fn token_finality_depth_for_network_type(network_type: NetworkType) -> u64 {
    match network_type {
        NetworkType::Mainnet => TOKEN_FINALITY_DEPTH_MAINNET,
        NetworkType::Testnet => TOKEN_FINALITY_DEPTH_TESTNET,
        NetworkType::Devnet => TOKEN_FINALITY_DEPTH_DEVNET,
        NetworkType::Simnet => TOKEN_FINALITY_DEPTH_SIMNET,
    }
}

fn token_replay_overlap_for_network_type(network_type: NetworkType) -> usize {
    match network_type {
        NetworkType::Mainnet => TOKEN_REPLAY_OVERLAP_MAINNET,
        NetworkType::Testnet => TOKEN_REPLAY_OVERLAP_TESTNET,
        NetworkType::Devnet => TOKEN_REPLAY_OVERLAP_DEVNET,
        NetworkType::Simnet => TOKEN_REPLAY_OVERLAP_SIMNET,
    }
}

fn max_retained_blocks(expected_finality_depth: u64, replay_overlap: usize) -> usize {
    let finality_depth = usize::try_from(expected_finality_depth).unwrap_or(usize::MAX / 4);
    finality_depth
        .saturating_add(replay_overlap)
        .saturating_add(TOKEN_HISTORY_RETENTION_SLACK_BLOCKS)
        .max(replay_overlap.saturating_add(1))
}

fn validate_cryptographic_binding_self_test() -> AtomicTokenResult<()> {
    let outpoint = TransactionOutpoint::new(BlockHash::from_u64_word(42), 0);
    let input = TransactionInput::new(outpoint, vec![1, 2, 3], 0, 0);
    let script = ScriptPublicKey::new(
        0,
        ScriptVec::from_slice(&[
            0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xAC,
        ]),
    );
    let output = TransactionOutput::new(123, script.clone());
    let entry = UtxoEntry::new(123, script, 0, false);

    let mut tx_base = Transaction::new(
        0,
        vec![input.clone()],
        vec![output.clone()],
        0,
        SUBNETWORK_ID_PAYLOAD,
        0,
        b"CAT\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00".to_vec(),
    );
    tx_base.finalize();

    let mut tx_payload_mutated = tx_base.clone();
    tx_payload_mutated.payload.push(0xAB);
    tx_payload_mutated.finalize();

    if tx_base.id() == tx_payload_mutated.id() {
        return Err(AtomicTokenError::CryptoBindingSelfTestFailed);
    }

    let mut tx_subnetwork_mutated = tx_base.clone();
    tx_subnetwork_mutated.subnetwork_id = SUBNETWORK_ID_NATIVE;
    tx_subnetwork_mutated.finalize();

    if tx_base.id() == tx_subnetwork_mutated.id() {
        return Err(AtomicTokenError::CryptoBindingSelfTestFailed);
    }

    let mut reused_a = SigHashReusedValues::new();
    let mut reused_b = SigHashReusedValues::new();
    let mut reused_c = SigHashReusedValues::new();
    let populated_a = PopulatedTransaction::new(&tx_base, vec![entry.clone()]);
    let populated_b = PopulatedTransaction::new(&tx_payload_mutated, vec![entry.clone()]);
    let populated_c = PopulatedTransaction::new(&tx_subnetwork_mutated, vec![entry]);
    let hash_a = calc_schnorr_signature_hash(&populated_a, 0, SIG_HASH_ALL, &mut reused_a);
    let hash_b = calc_schnorr_signature_hash(&populated_b, 0, SIG_HASH_ALL, &mut reused_b);
    let hash_c = calc_schnorr_signature_hash(&populated_c, 0, SIG_HASH_ALL, &mut reused_c);

    if hash_a == hash_b || hash_a == hash_c {
        return Err(AtomicTokenError::CryptoBindingSelfTestFailed);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{AtomicTokenSnapshotState, BlockJournal, SNAPSHOT_SCHEMA_VERSION};
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn unique_temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("cryptix-atomicindex-{label}-{nanos}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn minimal_snapshot(protocol_version: u16, network_id: &str) -> AtomicTokenSnapshot {
        let at_block_hash = BlockHash::from_u64_word(1);
        let window_start_parent_block_hash = BlockHash::from_u64_word(0);
        let mut state = AtomicTokenState::new(protocol_version, network_id.to_string());
        let state_hash = state.compute_state_hash();
        state.state_hash_by_block.insert(at_block_hash, state_hash);
        state.event_sequence_by_block.insert(at_block_hash, 0);
        state.applied_chain_order.push(at_block_hash);

        AtomicTokenSnapshot {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            protocol_version,
            network_id: network_id.to_string(),
            at_block_hash,
            at_daa_score: 123,
            state_hash_at_fp: state_hash,
            state_hash_at_window_start_parent: None,
            window_start_block_hash: at_block_hash,
            window_start_parent_block_hash,
            window_end_block_hash: at_block_hash,
            state: AtomicTokenSnapshotState {
                assets: state.assets,
                balances: state.balances,
                nonces: state.nonces,
                anchor_counts: state.anchor_counts,
                processed_ops: state.processed_ops,
                state_hash_by_block: state.state_hash_by_block,
                event_sequence_by_block: state.event_sequence_by_block,
                applied_chain_order: state.applied_chain_order,
                next_event_sequence: 0,
                events: Vec::new(),
            },
            journals_in_window: vec![(at_block_hash, BlockJournal::default())],
        }
    }

    #[test]
    fn load_state_from_path_clears_live_correct_on_restart() {
        let dir = unique_temp_dir("load-state");
        let path = dir.join("state.bin");
        let mut state = AtomicTokenState::new(TOKEN_PROTOCOL_VERSION, "cryptix-simnet".to_string());
        state.live_correct = true;
        persist_state_to_path(&path, &state).expect("persist state");

        let loaded =
            load_state_from_path(&path, TOKEN_PROTOCOL_VERSION, "cryptix-simnet").expect("load state").expect("state present");
        assert!(!loaded.live_correct);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn list_snapshot_catalog_requires_replay_sidecar() {
        let dir = unique_temp_dir("snapshot-catalog");
        let snapshot_path = dir.join("atomic-snapshot-1.bin");
        let snapshot = minimal_snapshot(TOKEN_PROTOCOL_VERSION, "cryptix-simnet");
        let snapshot_bytes = bincode::serialize(&snapshot).expect("encode snapshot");
        let replay_window_bytes = encode_replay_window_transfer(&snapshot).expect("encode replay");
        let manifest = build_snapshot_manifest(&snapshot_path, &snapshot_bytes, &replay_window_bytes, &snapshot).expect("manifest");
        let manifest_bytes = borsh::to_vec(&manifest).expect("encode manifest");

        fs::write(&snapshot_path, snapshot_bytes).expect("write snapshot");
        fs::write(snapshot_manifest_path(&snapshot_path), manifest_bytes).expect("write manifest");
        // Intentionally do not write the replay sidecar.

        let catalog = list_snapshot_catalog(&dir).expect("list catalog");
        assert!(catalog.is_empty());

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn validate_snapshot_blob_size_limits_rejects_oversized_values() {
        assert!(validate_snapshot_blob_size_limits(MAX_BOOTSTRAP_SNAPSHOT_FILE_SIZE_BYTES + 1, 1, "test").is_err());
        assert!(validate_snapshot_blob_size_limits(1, MAX_BOOTSTRAP_REPLAY_WINDOW_SIZE_BYTES + 1, "test").is_err());
    }

    #[test]
    fn prune_snapshot_catalog_entries_keeps_newest_snapshots() {
        let dir = unique_temp_dir("snapshot-prune");
        for i in 0..3u64 {
            let snapshot_path = dir.join(format!("atomic-snapshot-{i}.bin"));
            let mut snapshot = minimal_snapshot(TOKEN_PROTOCOL_VERSION, "cryptix-simnet");
            snapshot.at_daa_score = 100 + i;
            snapshot.at_block_hash = BlockHash::from_u64_word(10_000 + i);
            snapshot.window_start_block_hash = snapshot.at_block_hash;
            snapshot.window_end_block_hash = snapshot.at_block_hash;

            let snapshot_bytes = bincode::serialize(&snapshot).expect("encode snapshot");
            let replay_window_bytes = encode_replay_window_transfer(&snapshot).expect("encode replay");
            let manifest =
                build_snapshot_manifest(&snapshot_path, &snapshot_bytes, &replay_window_bytes, &snapshot).expect("manifest");
            let manifest_bytes = borsh::to_vec(&manifest).expect("encode manifest");

            fs::write(&snapshot_path, snapshot_bytes).expect("write snapshot");
            fs::write(snapshot_replay_path(&snapshot_path), replay_window_bytes).expect("write replay");
            fs::write(snapshot_manifest_path(&snapshot_path), manifest_bytes).expect("write manifest");
        }

        prune_snapshot_catalog_entries(&dir, TOKEN_PROTOCOL_VERSION, "cryptix-simnet", 2).expect("prune");
        let catalog = list_snapshot_catalog(&dir).expect("list catalog");
        assert_eq!(catalog.len(), 2);
        let mut daa_scores = catalog.into_iter().map(|entry| entry.manifest.at_daa_score).collect::<Vec<_>>();
        daa_scores.sort_unstable();
        assert_eq!(daa_scores, vec![101, 102]);

        let _ = fs::remove_dir_all(dir);
    }
}
