use crate::{
    error::{AtomicTokenError, AtomicTokenResult},
    payload::TokenOp,
    state::{
        AtomicTokenHealth, AtomicTokenReadContext, AtomicTokenReadView, AtomicTokenRuntimeState, AtomicTokenState,
        AtomicTokenStateFootprint, BalanceKey, LiquidityHolderAddressState, NonceKey, ProcessedOp, TokenAsset, TokenEvent,
        TokenHolderEntry, TokenOwnerBalanceEntry,
    },
    storage_v2::{AtomicStorageSnapshotCounts, AtomicStorageV2, ATOMIC_REVALIDATION_VERSION},
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
    debug, info,
    task::service::{AsyncService, AsyncServiceFuture},
    trace, warn,
};
use cryptix_notify::{connection::ChannelType, listener::ListenerLifespan, scope::VirtualChainChangedScope};
use cryptix_utils::{channel::Channel, triggers::SingleTrigger};
use hex::encode as hex_encode;
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{BufReader, BufWriter, ErrorKind, Read, Seek, SeekFrom, Write},
    path::Path,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex as StdMutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex, Notify};

const SERVICE_IDENT: &str = "cryptix-atomic-service";
const TOKEN_PROTOCOL_VERSION: u16 = 6;

const TOKEN_FINALITY_DEPTH_MAINNET: u64 = 86_400;
const TOKEN_FINALITY_DEPTH_TESTNET: u64 = 86_400;
const TOKEN_FINALITY_DEPTH_DEVNET: u64 = 86_400;
const TOKEN_FINALITY_DEPTH_SIMNET: u64 = 432_000;
const TOKEN_REPLAY_OVERLAP_MAINNET: usize = 12_000;
const TOKEN_REPLAY_OVERLAP_TESTNET: usize = 12_000;
const TOKEN_REPLAY_OVERLAP_DEVNET: usize = 12_000;
const TOKEN_REPLAY_OVERLAP_SIMNET: usize = 120_000;
const TOKEN_HISTORY_RETENTION_SLACK_BLOCKS: usize = 2048;
const SNAPSHOT_MANIFEST_DOMAIN: &[u8] = b"CRYPTIX_ATOMIC_SNAPSHOT_MANIFEST_V2";
const SNAPSHOT_ID_DOMAIN: &[u8] = b"CAT_SNAPSHOT_ID_V2";
const SNAPSHOT_CHUNK_SIZE_DEFAULT: usize = 1024 * 1024;
const SNAPSHOT_CHUNK_SIZE_MAX: usize = 4 * 1024 * 1024;
pub const MAX_BOOTSTRAP_SNAPSHOT_FILE_SIZE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub const MAX_BOOTSTRAP_REPLAY_WINDOW_SIZE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const SNAPSHOT_IMPORT_CHUNK_KEYS: usize = 4096;
const BOOTSTRAP_STORE_MAX_SNAPSHOTS_PER_NETWORK: usize = 16;
const ATOMIC_TEMP_DIR_MAX_AGE: Duration = Duration::from_secs(3600);
const ATOMIC_PROGRESS_LOG_INTERVAL: Duration = Duration::from_secs(30);
const ATOMIC_LONG_OPERATION_LOG_INTERVAL: Duration = Duration::from_secs(5);
const DEGRADED_READ_WARN_INTERVAL: Duration = Duration::from_secs(10);
const P2P_AUDIT_RENDEZVOUS_DAA_LAG: u64 = 60;

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
struct SnapshotManifestV2 {
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
    state_hash_at_window_start_parent: Option<[u8; 32]>,
    window_start_block_hash: [u8; 32],
    window_start_parent_block_hash: [u8; 32],
    window_end_block_hash: [u8; 32],
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct ReplayWindowTransferV2 {
    protocol_version: u16,
    network_id: String,
    window_start_block_hash: [u8; 32],
    window_end_block_hash: [u8; 32],
    journals_in_window: Vec<(BlockHash, crate::state::BlockJournal)>,
}

#[derive(serde::Serialize)]
struct ReplayWindowTransferV2Ref<'a> {
    protocol_version: u16,
    network_id: &'a str,
    window_start_block_hash: [u8; 32],
    window_end_block_hash: [u8; 32],
    journals_in_window: &'a [(BlockHash, crate::state::BlockJournal)],
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct SnapshotFileHeaderV2 {
    schema_version: u16,
    protocol_version: u16,
    network_id: String,
    at_block_hash: BlockHash,
    at_daa_score: u64,
    state_hash_at_fp: [u8; 32],
    state_hash_at_window_start_parent: Option<[u8; 32]>,
    window_start_block_hash: BlockHash,
    window_start_parent_block_hash: BlockHash,
    window_end_block_hash: BlockHash,
    next_event_sequence: u64,
    counts: AtomicStorageSnapshotCounts,
}

#[derive(Clone, Debug)]
struct ValidatedSnapshotFileV2 {
    header: SnapshotFileHeaderV2,
    replay_window: ReplayWindowTransferV2,
}

#[derive(Clone, Debug)]
struct SnapshotCatalogEntry {
    snapshot_id_hex: String,
    snapshot_path: PathBuf,
    manifest: SnapshotManifestV2,
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
    processed_chain_blocks: AtomicU64,
    progress_log: StdMutex<AtomicProgressLogState>,
    state_progress_notify: Notify,
    state: Mutex<AtomicTokenState>,
    state_store: Arc<AtomicStorageV2>,
}

#[derive(Default)]
struct AtomicProgressLogState {
    last_log: Option<Instant>,
    last_runtime_state: Option<AtomicTokenRuntimeState>,
    last_degraded_read_log: Option<Instant>,
}

impl AtomicTokenProcessor {
    fn new(
        consensus_manager: Arc<ConsensusManager>,
        max_retained_blocks: usize,
        state: AtomicTokenState,
        state_store: Arc<AtomicStorageV2>,
    ) -> Self {
        Self {
            consensus_manager,
            max_retained_blocks,
            operation_lock: Default::default(),
            bootstrap_in_progress: AtomicBool::new(true),
            processed_chain_blocks: AtomicU64::new(0),
            progress_log: Default::default(),
            state_progress_notify: Notify::new(),
            state: Mutex::new(state),
            state_store,
        }
    }

    fn set_bootstrap_in_progress(&self, value: bool) {
        self.bootstrap_in_progress.store(value, Ordering::SeqCst);
        self.notify_state_progress();
    }

    fn notify_state_progress(&self) {
        self.state_progress_notify.notify_waiters();
    }

    async fn collect_auth_inputs_for_added_blocks(
        &self,
        added_chain_block_hashes: &[BlockHash],
    ) -> AtomicTokenResult<HashMap<TransactionOutpoint, UtxoEntry>> {
        let consensus = self.consensus_manager.consensus();
        let session = consensus.session().await;
        let mut auth_inputs = HashMap::new();
        let total = added_chain_block_hashes.len();
        let should_log_progress = total >= 1024;
        let mut last_log = Instant::now();
        if should_log_progress {
            info!("[{IDENT}] collecting Atomic auth inputs for {} replay block(s)", total);
        }
        for (idx, block_hash) in added_chain_block_hashes.iter().copied().enumerate() {
            let utxo_diff = session.async_get_block_utxo_diff(block_hash).await?;
            auth_inputs.extend(utxo_diff.remove.iter().map(|(outpoint, entry)| (*outpoint, entry.clone())));
            if should_log_progress && last_log.elapsed() >= ATOMIC_LONG_OPERATION_LOG_INTERVAL {
                info!("[{IDENT}] collecting Atomic auth inputs progress: {}/{} block(s)", idx.saturating_add(1), total);
                last_log = Instant::now();
            }
        }
        if should_log_progress {
            info!("[{IDENT}] collected Atomic auth inputs for {} replay block(s): {} spent output(s)", total, auth_inputs.len());
        }
        Ok(auth_inputs)
    }

    async fn process(&self, notification: ConsensusNotification) -> AtomicTokenResult<()> {
        let _operation_guard = self.operation_lock.lock().await;
        match notification {
            ConsensusNotification::UtxosChanged(_) => Ok(()),
            ConsensusNotification::VirtualChainChanged(msg) => {
                let already_applied_prefix_len = {
                    let state = self.state.lock().await;
                    if msg.removed_chain_block_hashes.is_empty() {
                        msg.added_chain_block_hashes
                            .iter()
                            .take_while(|block_hash| state.state_hash_by_block.contains_key(block_hash))
                            .count()
                    } else {
                        0
                    }
                };
                let msg = if already_applied_prefix_len == msg.added_chain_block_hashes.len()
                    && msg.removed_chain_block_hashes.is_empty()
                {
                    return Ok(());
                } else if already_applied_prefix_len > 0 {
                    debug!("[{IDENT}] skipping {} already-applied Atomic virtual-chain block(s)", already_applied_prefix_len);
                    VirtualChainChangedNotification::new(
                        Arc::new(msg.added_chain_block_hashes.iter().skip(already_applied_prefix_len).copied().collect()),
                        Arc::new(Vec::new()),
                        Arc::new(msg.added_chain_blocks_acceptance_data.iter().skip(already_applied_prefix_len).cloned().collect()),
                    )
                } else {
                    msg
                };
                let added_count = msg.added_chain_block_hashes.len();
                let removed_count = msg.removed_chain_block_hashes.len();
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
                    let _ = self.state_store.persist_runtime_flags(
                        state.applied_chain_order.last().copied(),
                        state.applied_chain_order.len() as u64,
                        state.degraded,
                        state.next_event_sequence,
                    );
                    drop(state);
                    self.notify_state_progress();
                    return Err(err);
                }
                if let Some(pruned) = state.prune_history_with_details(self.max_retained_blocks) {
                    if let Err(err) = self.state_store.prune_history(
                        &pruned.pruned_hashes,
                        &state.applied_chain_order,
                        pruned.last_pruned_event_sequence,
                    ) {
                        if !state.degraded {
                            warn!("[{IDENT}] marking Cryptix Atomic degraded after history prune persistence error: {err}");
                        }
                        state.mark_degraded();
                        let _ = self.state_store.persist_runtime_flags(
                            state.applied_chain_order.last().copied(),
                            state.applied_chain_order.len() as u64,
                            state.degraded,
                            state.next_event_sequence,
                        );
                        drop(state);
                        self.notify_state_progress();
                        return Err(err);
                    }
                    if pruned.pruned_processed_ops {
                        trace!("[{IDENT}] Cryptix Atomic pruning removed processed op guard entries");
                    }
                }
                let retained_blocks = state.applied_chain_order.len();
                let footprint = state.footprint();
                let state_store_bytes = self.state_store.approximate_size_bytes();
                drop(state);

                let health = self.health().await;
                self.maybe_log_progress(added_count, removed_count, retained_blocks, health, footprint, state_store_bytes);
                self.notify_state_progress();
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn maybe_log_progress(
        &self,
        added_count: usize,
        removed_count: usize,
        retained_blocks: usize,
        health: AtomicTokenHealth,
        footprint: AtomicTokenStateFootprint,
        state_store_bytes: Option<u64>,
    ) {
        if added_count == 0 && removed_count == 0 {
            return;
        }

        let total_processed =
            self.processed_chain_blocks.fetch_add(added_count as u64, Ordering::SeqCst).saturating_add(added_count as u64);
        let now = Instant::now();
        let mut progress_log = self.progress_log.lock().expect("Atomic progress log mutex poisoned");
        let state_changed = progress_log.last_runtime_state != Some(health.runtime_state);
        let should_log_by_time =
            progress_log.last_log.map(|last_log| now.duration_since(last_log) >= ATOMIC_PROGRESS_LOG_INTERVAL).unwrap_or(true);
        if !state_changed && !should_log_by_time {
            return;
        }

        progress_log.last_log = Some(now);
        progress_log.last_runtime_state = Some(health.runtime_state);
        let last_applied = health.last_applied_block.map(|hash| hash.to_string()).unwrap_or_else(|| "<none>".to_string());
        info!(
            "[{IDENT}] Cryptix Atomic indexed chain progress: +{}/-{} blocks ({} processed since startup, {} retained), runtime={}, live_correct={}, last_applied={}, event_seq={}, state_hash={}, events={}, journals={}, checkpoints={}, state_store={}",
            added_count,
            removed_count,
            total_processed,
            retained_blocks,
            health.runtime_state.as_str(),
            health.live_correct,
            last_applied,
            health.last_sequence,
            short_hex_for_log(&health.current_state_hash),
            footprint.events,
            footprint.block_journals,
            footprint.state_hash_checkpoints,
            state_store_bytes.map(format_bytes_for_log).unwrap_or_else(|| "n/a".to_string()),
        );
    }

    async fn state_hash(&self) -> [u8; 32] {
        self.state.lock().await.get_state_hash()
    }

    async fn local_health(&self) -> AtomicTokenHealth {
        let bootstrap_in_progress = self.bootstrap_in_progress.load(Ordering::SeqCst);
        let state = self.state.lock().await;
        let mut health = state.get_health();
        health.bootstrap_in_progress = bootstrap_in_progress;
        health.runtime_state = state.runtime_state(bootstrap_in_progress);
        health
    }

    async fn health(&self) -> AtomicTokenHealth {
        self.local_health().await
    }

    async fn consensus_sink(&self) -> BlockHash {
        let consensus = self.consensus_manager.consensus();
        let session = consensus.session().await;
        session.async_get_sink().await
    }

    async fn latest_read_sink(&self, requested_at_block_hash: Option<BlockHash>) -> Option<Option<BlockHash>> {
        if requested_at_block_hash.is_some() {
            return Some(None);
        }

        let target_sink = self.consensus_sink().await;
        let mut logged_wait = false;
        loop {
            let notified = self.state_progress_notify.notified();
            let current_sink = self.consensus_sink().await;
            let bootstrap_in_progress = self.bootstrap_in_progress.load(Ordering::SeqCst);
            let (last_applied, target_is_retained, runtime_state) = {
                let state = self.state.lock().await;
                (
                    state.applied_chain_order.last().copied(),
                    state.state_hash_by_block.contains_key(&target_sink),
                    state.runtime_state(bootstrap_in_progress),
                )
            };

            if target_is_retained || last_applied == Some(target_sink) || last_applied == Some(current_sink) {
                return Some(None);
            }

            if matches!(runtime_state, AtomicTokenRuntimeState::Degraded | AtomicTokenRuntimeState::NotReady) && !bootstrap_in_progress
            {
                let last_applied_for_log = last_applied.map(|hash| hash.to_string()).unwrap_or_else(|| "<none>".to_string());
                if matches!(runtime_state, AtomicTokenRuntimeState::Degraded) {
                    let should_log = {
                        let now = Instant::now();
                        let mut progress_log = self.progress_log.lock().expect("Atomic progress log mutex poisoned");
                        let should_log = progress_log
                            .last_degraded_read_log
                            .map(|last| now.duration_since(last) >= DEGRADED_READ_WARN_INTERVAL)
                            .unwrap_or(true);
                        if should_log {
                            progress_log.last_degraded_read_log = Some(now);
                        }
                        should_log
                    };
                    if should_log {
                        warn!(
                            "[{IDENT}] refusing latest Atomic read while indexer is degraded: last_applied={}, target_sink={}, current_sink={}",
                            last_applied_for_log, target_sink, current_sink
                        );
                    }
                } else {
                    debug!(
                        "[{IDENT}] latest Atomic read unavailable while indexer is initializing: last_applied={}, target_sink={}, current_sink={}",
                        last_applied_for_log, target_sink, current_sink
                    );
                }
                return None;
            }

            if !logged_wait {
                debug!(
                    "[{IDENT}] latest Atomic read waiting for indexer catch-up: last_applied={}, target_sink={}, current_sink={}",
                    last_applied.map(|hash| hash.to_string()).unwrap_or_else(|| "<none>".to_string()),
                    target_sink,
                    current_sink
                );
                logged_wait = true;
            }
            notified.await;
        }
    }

    fn state_matches_latest_sink(state: &AtomicTokenState, latest_sink: Option<BlockHash>) -> bool {
        match latest_sink {
            Some(sink) => state.applied_chain_order.last().copied() == Some(sink),
            None => true,
        }
    }

    async fn balance(&self, asset_id: [u8; 32], owner_id: [u8; 32]) -> u128 {
        self.state.lock().await.get_balance(asset_id, owner_id)
    }

    async fn owner_nonce(&self, owner_id: [u8; 32]) -> u64 {
        self.state.lock().await.get_owner_nonce(owner_id)
    }

    async fn token_nonce(&self, owner_id: [u8; 32], asset_id: [u8; 32]) -> u64 {
        self.state.lock().await.get_token_nonce(owner_id, asset_id)
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

    async fn read_context(
        &self,
        requested_at_block_hash: Option<BlockHash>,
        fallback_block_hash: BlockHash,
    ) -> Option<AtomicTokenReadContext> {
        let latest_sink = self.latest_read_sink(requested_at_block_hash).await?;
        let bootstrap_in_progress = self.bootstrap_in_progress.load(Ordering::SeqCst);
        let state = self.state.lock().await;
        if !Self::state_matches_latest_sink(&state, latest_sink) {
            return None;
        }
        let runtime_state = state.runtime_state(bootstrap_in_progress);
        match requested_at_block_hash {
            Some(at_block_hash) => state.materialize_context_at_block(at_block_hash, runtime_state),
            None => Some(state.materialize_latest_context(fallback_block_hash, runtime_state)),
        }
    }

    async fn balance_read(
        &self,
        asset_id: [u8; 32],
        owner_id: [u8; 32],
        requested_at_block_hash: Option<BlockHash>,
        fallback_block_hash: BlockHash,
    ) -> Option<(AtomicTokenReadContext, u128)> {
        let latest_sink = self.latest_read_sink(requested_at_block_hash).await?;
        let bootstrap_in_progress = self.bootstrap_in_progress.load(Ordering::SeqCst);
        let state = self.state.lock().await;
        if !Self::state_matches_latest_sink(&state, latest_sink) {
            return None;
        }
        let runtime_state = state.runtime_state(bootstrap_in_progress);
        let context = match requested_at_block_hash {
            Some(at_block_hash) => state.materialize_context_at_block(at_block_hash, runtime_state)?,
            None => state.materialize_latest_context(fallback_block_hash, runtime_state),
        };
        let key = BalanceKey { asset_id, owner_id };
        let balance = match requested_at_block_hash {
            Some(at_block_hash) => state.get_balance_at_block(key, at_block_hash)?,
            None => state.get_balance(asset_id, owner_id),
        };
        Some((context, balance))
    }

    async fn nonce_read(
        &self,
        key: NonceKey,
        requested_at_block_hash: Option<BlockHash>,
        fallback_block_hash: BlockHash,
    ) -> Option<(AtomicTokenReadContext, u64)> {
        let latest_sink = self.latest_read_sink(requested_at_block_hash).await?;
        let bootstrap_in_progress = self.bootstrap_in_progress.load(Ordering::SeqCst);
        let state = self.state.lock().await;
        if !Self::state_matches_latest_sink(&state, latest_sink) {
            return None;
        }
        let runtime_state = state.runtime_state(bootstrap_in_progress);
        let context = match requested_at_block_hash {
            Some(at_block_hash) => state.materialize_context_at_block(at_block_hash, runtime_state)?,
            None => state.materialize_latest_context(fallback_block_hash, runtime_state),
        };
        let nonce = match requested_at_block_hash {
            Some(at_block_hash) => state.get_nonce_at_block(key, at_block_hash)?,
            None => match key.scope_kind {
                crate::state::NONCE_SCOPE_ASSET => state.get_token_nonce(key.owner_id, key.scope_id),
                _ => state.get_owner_nonce(key.owner_id),
            },
        };
        Some((context, nonce))
    }

    async fn anchor_count_read(
        &self,
        owner_id: [u8; 32],
        requested_at_block_hash: Option<BlockHash>,
        fallback_block_hash: BlockHash,
    ) -> Option<(AtomicTokenReadContext, u64)> {
        let latest_sink = self.latest_read_sink(requested_at_block_hash).await?;
        let bootstrap_in_progress = self.bootstrap_in_progress.load(Ordering::SeqCst);
        let state = self.state.lock().await;
        if !Self::state_matches_latest_sink(&state, latest_sink) {
            return None;
        }
        let runtime_state = state.runtime_state(bootstrap_in_progress);
        let context = match requested_at_block_hash {
            Some(at_block_hash) => state.materialize_context_at_block(at_block_hash, runtime_state)?,
            None => state.materialize_latest_context(fallback_block_hash, runtime_state),
        };
        let anchor_count = match requested_at_block_hash {
            Some(at_block_hash) => state.get_anchor_count_at_block(owner_id, at_block_hash)?,
            None => state.get_anchor_count(owner_id),
        };
        Some((context, anchor_count))
    }

    async fn asset_read(
        &self,
        asset_id: [u8; 32],
        requested_at_block_hash: Option<BlockHash>,
        fallback_block_hash: BlockHash,
    ) -> Option<(AtomicTokenReadContext, Option<TokenAsset>)> {
        let latest_sink = self.latest_read_sink(requested_at_block_hash).await?;
        let bootstrap_in_progress = self.bootstrap_in_progress.load(Ordering::SeqCst);
        let state = self.state.lock().await;
        if !Self::state_matches_latest_sink(&state, latest_sink) {
            return None;
        }
        let runtime_state = state.runtime_state(bootstrap_in_progress);
        let context = match requested_at_block_hash {
            Some(at_block_hash) => state.materialize_context_at_block(at_block_hash, runtime_state)?,
            None => state.materialize_latest_context(fallback_block_hash, runtime_state),
        };
        let asset = match requested_at_block_hash {
            Some(at_block_hash) => state.get_asset_at_block(asset_id, at_block_hash)?,
            None => state.get_asset(asset_id),
        };
        Some((context, asset))
    }

    async fn op_status_read(
        &self,
        txid: BlockHash,
        requested_at_block_hash: Option<BlockHash>,
        fallback_block_hash: BlockHash,
    ) -> Option<(AtomicTokenReadContext, Option<ProcessedOp>)> {
        let latest_sink = self.latest_read_sink(requested_at_block_hash).await?;
        let bootstrap_in_progress = self.bootstrap_in_progress.load(Ordering::SeqCst);
        let state = self.state.lock().await;
        if !Self::state_matches_latest_sink(&state, latest_sink) {
            return None;
        }
        let runtime_state = state.runtime_state(bootstrap_in_progress);
        let context = match requested_at_block_hash {
            Some(at_block_hash) => state.materialize_context_at_block(at_block_hash, runtime_state)?,
            None => state.materialize_latest_context(fallback_block_hash, runtime_state),
        };
        let status = match requested_at_block_hash {
            Some(at_block_hash) => state.get_processed_op_at_block(txid, at_block_hash)?,
            None => state.get_op_status(txid),
        };
        Some((context, status))
    }

    async fn assets_page(
        &self,
        offset: usize,
        limit: usize,
        query: String,
        requested_at_block_hash: Option<BlockHash>,
        fallback_block_hash: BlockHash,
    ) -> Option<(AtomicTokenReadContext, Vec<TokenAsset>, u64)> {
        let latest_sink = self.latest_read_sink(requested_at_block_hash).await?;
        let bootstrap_in_progress = self.bootstrap_in_progress.load(Ordering::SeqCst);
        let state = self.state.lock().await;
        if !Self::state_matches_latest_sink(&state, latest_sink) {
            return None;
        }
        let runtime_state = state.runtime_state(bootstrap_in_progress);
        match requested_at_block_hash {
            Some(at_block_hash) => {
                let context = state.materialize_context_at_block(at_block_hash, runtime_state)?;
                let (assets, total) = state.indexed_assets_page_at_block(offset, limit, &query, at_block_hash)?;
                Some((context, assets, total))
            }
            None => {
                let context = state.materialize_latest_context(fallback_block_hash, runtime_state);
                let (assets, total) = state.indexed_assets_page(offset, limit, &query);
                Some((context, assets, total))
            }
        }
    }

    async fn simulation_view(
        &self,
        owner_id: [u8; 32],
        op: &TokenOp,
        requested_at_block_hash: Option<BlockHash>,
        fallback_block_hash: BlockHash,
    ) -> Option<AtomicTokenReadView> {
        let latest_sink = self.latest_read_sink(requested_at_block_hash).await?;
        let bootstrap_in_progress = self.bootstrap_in_progress.load(Ordering::SeqCst);
        let state = self.state.lock().await;
        if !Self::state_matches_latest_sink(&state, latest_sink) {
            return None;
        }
        let runtime_state = state.runtime_state(bootstrap_in_progress);
        let context = match requested_at_block_hash {
            Some(at_block_hash) => state.materialize_context_at_block(at_block_hash, runtime_state)?,
            None => state.materialize_latest_context(fallback_block_hash, runtime_state),
        };
        let mut view = AtomicTokenReadView {
            at_block_hash: context.at_block_hash,
            state_hash: context.state_hash,
            is_degraded: context.is_degraded,
            runtime_state: context.runtime_state,
            event_sequence_cutoff: context.event_sequence_cutoff,
            assets: HashMap::new(),
            balances: HashMap::new(),
            nonces: HashMap::new(),
            anchor_counts: HashMap::new(),
            processed_ops: HashMap::new(),
            known_owner_addresses: HashMap::new(),
        };

        let nonce_key = crate::state::nonce_key_for_op(owner_id, op);
        let nonce = match requested_at_block_hash {
            Some(at_block_hash) => state.get_nonce_at_block(nonce_key, at_block_hash)?,
            None => match nonce_key.scope_kind {
                crate::state::NONCE_SCOPE_ASSET => state.get_token_nonce(owner_id, nonce_key.scope_id),
                _ => state.get_owner_nonce(owner_id),
            },
        };
        view.nonces.insert(nonce_key, nonce);

        fn read_asset(
            state: &AtomicTokenState,
            requested_at_block_hash: Option<BlockHash>,
            asset_id: [u8; 32],
        ) -> Option<Option<TokenAsset>> {
            match requested_at_block_hash {
                Some(at_block_hash) => state.get_asset_at_block(asset_id, at_block_hash),
                None => Some(state.get_asset(asset_id)),
            }
        }

        fn read_balance(
            state: &AtomicTokenState,
            requested_at_block_hash: Option<BlockHash>,
            asset_id: [u8; 32],
            owner_id: [u8; 32],
        ) -> Option<u128> {
            let key = BalanceKey { asset_id, owner_id };
            match requested_at_block_hash {
                Some(at_block_hash) => state.get_balance_at_block(key, at_block_hash),
                None => Some(state.get_balance(asset_id, owner_id)),
            }
        }

        match op {
            TokenOp::CreateAsset(_) | TokenOp::CreateAssetWithMint(_) | TokenOp::CreateLiquidityAsset(_) => {}
            TokenOp::Transfer(op) => {
                if let Some(asset) = read_asset(&state, requested_at_block_hash, op.asset_id)? {
                    view.assets.insert(op.asset_id, asset);
                }
                let sender_key = BalanceKey { asset_id: op.asset_id, owner_id };
                let sender_balance = read_balance(&state, requested_at_block_hash, op.asset_id, owner_id)?;
                if sender_balance > 0 {
                    view.balances.insert(sender_key, sender_balance);
                }
                let receiver_key = BalanceKey { asset_id: op.asset_id, owner_id: op.to_owner_id };
                let receiver_balance = read_balance(&state, requested_at_block_hash, op.asset_id, op.to_owner_id)?;
                if receiver_balance > 0 {
                    view.balances.insert(receiver_key, receiver_balance);
                }
            }
            TokenOp::Mint(op) => {
                if let Some(asset) = read_asset(&state, requested_at_block_hash, op.asset_id)? {
                    view.assets.insert(op.asset_id, asset);
                }
                let receiver_key = BalanceKey { asset_id: op.asset_id, owner_id: op.to_owner_id };
                let receiver_balance = read_balance(&state, requested_at_block_hash, op.asset_id, op.to_owner_id)?;
                if receiver_balance > 0 {
                    view.balances.insert(receiver_key, receiver_balance);
                }
            }
            TokenOp::Burn(op) => {
                if let Some(asset) = read_asset(&state, requested_at_block_hash, op.asset_id)? {
                    view.assets.insert(op.asset_id, asset);
                }
                let sender_key = BalanceKey { asset_id: op.asset_id, owner_id };
                let sender_balance = read_balance(&state, requested_at_block_hash, op.asset_id, owner_id)?;
                if sender_balance > 0 {
                    view.balances.insert(sender_key, sender_balance);
                }
            }
            TokenOp::BuyLiquidityExactIn(op) => {
                if let Some(asset) = read_asset(&state, requested_at_block_hash, op.asset_id)? {
                    view.assets.insert(op.asset_id, asset);
                }
            }
            TokenOp::SellLiquidityExactIn(op) => {
                if let Some(asset) = read_asset(&state, requested_at_block_hash, op.asset_id)? {
                    view.assets.insert(op.asset_id, asset);
                }
                let sender_key = BalanceKey { asset_id: op.asset_id, owner_id };
                let sender_balance = read_balance(&state, requested_at_block_hash, op.asset_id, owner_id)?;
                if sender_balance > 0 {
                    view.balances.insert(sender_key, sender_balance);
                }
            }
            TokenOp::ClaimLiquidityFees(op) => {
                if let Some(asset) = read_asset(&state, requested_at_block_hash, op.asset_id)? {
                    view.assets.insert(op.asset_id, asset);
                }
            }
        }

        Some(view)
    }

    async fn indexed_balances_by_owner(
        &self,
        owner_id: [u8; 32],
        include_assets: bool,
        requested_at_block_hash: Option<BlockHash>,
        fallback_block_hash: BlockHash,
    ) -> Option<(AtomicTokenReadContext, Vec<TokenOwnerBalanceEntry>)> {
        let latest_sink = self.latest_read_sink(requested_at_block_hash).await?;
        let bootstrap_in_progress = self.bootstrap_in_progress.load(Ordering::SeqCst);
        let state = self.state.lock().await;
        if !Self::state_matches_latest_sink(&state, latest_sink) {
            return None;
        }
        let runtime_state = state.runtime_state(bootstrap_in_progress);
        match requested_at_block_hash {
            Some(at_block_hash) => {
                let context = state.materialize_context_at_block(at_block_hash, runtime_state)?;
                let balances = state.indexed_balances_by_owner_at_block(owner_id, include_assets, at_block_hash)?;
                Some((context, balances))
            }
            None => {
                let context = state.materialize_latest_context(fallback_block_hash, runtime_state);
                let balances = state.indexed_balances_by_owner(owner_id, include_assets);
                Some((context, balances))
            }
        }
    }

    async fn indexed_holders_by_asset(
        &self,
        asset_id: [u8; 32],
        requested_at_block_hash: Option<BlockHash>,
        fallback_block_hash: BlockHash,
    ) -> Option<(AtomicTokenReadContext, Vec<TokenHolderEntry>)> {
        let latest_sink = self.latest_read_sink(requested_at_block_hash).await?;
        let bootstrap_in_progress = self.bootstrap_in_progress.load(Ordering::SeqCst);
        let state = self.state.lock().await;
        if !Self::state_matches_latest_sink(&state, latest_sink) {
            return None;
        }
        let runtime_state = state.runtime_state(bootstrap_in_progress);
        match requested_at_block_hash {
            Some(at_block_hash) => {
                let context = state.materialize_context_at_block(at_block_hash, runtime_state)?;
                let holders = state.indexed_holders_by_asset_at_block(asset_id, at_block_hash)?;
                Some((context, holders))
            }
            None => {
                let context = state.materialize_latest_context(fallback_block_hash, runtime_state);
                let holders = state.indexed_holders_by_asset(asset_id);
                Some((context, holders))
            }
        }
    }

    async fn indexed_liquidity_holders(
        &self,
        asset_id: [u8; 32],
        requested_at_block_hash: Option<BlockHash>,
        fallback_block_hash: BlockHash,
    ) -> Option<(AtomicTokenReadContext, Option<TokenAsset>, Vec<TokenHolderEntry>, HashMap<[u8; 32], LiquidityHolderAddressState>)>
    {
        let latest_sink = self.latest_read_sink(requested_at_block_hash).await?;
        let bootstrap_in_progress = self.bootstrap_in_progress.load(Ordering::SeqCst);
        let state = self.state.lock().await;
        if !Self::state_matches_latest_sink(&state, latest_sink) {
            return None;
        }
        let runtime_state = state.runtime_state(bootstrap_in_progress);
        match requested_at_block_hash {
            Some(at_block_hash) => {
                let context = state.materialize_context_at_block(at_block_hash, runtime_state)?;
                let asset = state.get_asset_at_block(asset_id, at_block_hash)?;
                let holders = state.indexed_holders_by_asset_at_block(asset_id, at_block_hash)?;
                let pool_holder_addresses =
                    asset.as_ref().and_then(|asset| asset.liquidity.as_ref()).map(|pool| &pool.holder_addresses);
                let owner_to_address_state = holders
                    .iter()
                    .filter_map(|(owner_id, _)| {
                        pool_holder_addresses.and_then(|addresses| addresses.get(owner_id)).map(|holder| (*owner_id, holder.clone()))
                    })
                    .collect();
                Some((context, asset, holders, owner_to_address_state))
            }
            None => {
                let context = state.materialize_latest_context(fallback_block_hash, runtime_state);
                let asset = state.get_asset(asset_id);
                let holders = state.indexed_holders_by_asset(asset_id);
                let owner_to_address_state = state.indexed_liquidity_holder_addresses(asset_id, &holders);
                Some((context, asset, holders, owner_to_address_state))
            }
        }
    }

    async fn mark_degraded_best_effort(&self, reason: &str) {
        let mut state = self.state.lock().await;
        if !state.degraded {
            warn!("[{IDENT}] marking Cryptix Atomic degraded: {reason}");
        }
        state.mark_degraded();
        if let Err(err) = self.state_store.persist_runtime_flags(
            state.applied_chain_order.last().copied(),
            state.applied_chain_order.len() as u64,
            state.degraded,
            state.next_event_sequence,
        ) {
            warn!("[{IDENT}] failed persisting degraded Cryptix Atomic state: {err}");
        }
        drop(state);
        self.notify_state_progress();
    }
}

pub struct AtomicTokenService {
    recv_channel: Receiver<ConsensusNotification>,
    processor: Arc<AtomicTokenProcessor>,
    shutdown: SingleTrigger,
    retained_revalidation_failed: AtomicBool,
    expected_finality_depth: u64,
    replay_overlap: usize,
    max_retained_blocks: usize,
    payload_hf_activation_daa_score: u64,
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
        let state_store = Arc::new(AtomicStorageV2::open(
            atomic_data_dir.join("state-v2"),
            TOKEN_PROTOCOL_VERSION,
            network_id.clone(),
            config.params.genesis.hash,
        )?);
        let mut state =
            state_store.load_runtime_state()?.unwrap_or_else(|| AtomicTokenState::new(TOKEN_PROTOCOL_VERSION, network_id.clone()));
        state.attach_state_store(state_store.clone());
        state.set_payload_hf_activation_daa_score(config.params.payload_hf_activation_daa_score);
        if state.degraded && !state.has_verified_state() {
            warn!(
                "[{IDENT}] persisted Atomic state is degraded but has no verified chain anchor; resetting Atomic index state so local block replay can rebuild it"
            );
            state = AtomicTokenState::new(TOKEN_PROTOCOL_VERSION, network_id.clone());
            state.attach_state_store(state_store.clone());
            state.set_payload_hf_activation_daa_score(config.params.payload_hf_activation_daa_score);
            state_store.persist_state(&state)?;
        }
        state.rebuild_runtime_caches();
        let state_store_bytes = state_store.approximate_size_bytes();
        log_state_footprint("loaded", state.footprint(), state_store_bytes);

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
            processor: Arc::new(AtomicTokenProcessor::new(consensus_manager, max_retained_blocks, state, state_store)),
            shutdown: Default::default(),
            retained_revalidation_failed: AtomicBool::new(false),
            expected_finality_depth,
            replay_overlap,
            max_retained_blocks,
            payload_hf_activation_daa_score: config.params.payload_hf_activation_daa_score,
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

    pub async fn get_local_health(&self) -> AtomicTokenHealth {
        self.processor.local_health().await
    }

    pub async fn get_state_hash_at_block(&self, at_block_hash: BlockHash) -> Option<[u8; 32]> {
        self.processor.state.lock().await.get_state_hash_at_block(at_block_hash)
    }

    pub async fn get_p2p_audit_context(&self) -> AtomicTokenResult<Option<(AtomicTokenReadContext, u64)>> {
        let (anchor_hash, anchor_daa_score) = self.current_p2p_audit_anchor().await?;
        Ok(self.p2p_audit_context_from_retained_checkpoint(anchor_hash).await?.map(|context| (context, anchor_daa_score)))
    }

    pub async fn get_p2p_audit_state_hash_at_block(&self, at_block_hash: BlockHash) -> Option<[u8; 32]> {
        self.p2p_audit_context_from_retained_checkpoint(at_block_hash).await.ok().flatten().map(|context| context.state_hash)
    }

    async fn p2p_audit_context_from_retained_checkpoint(
        &self,
        at_block_hash: BlockHash,
    ) -> AtomicTokenResult<Option<AtomicTokenReadContext>> {
        if self.processor.bootstrap_in_progress.load(Ordering::SeqCst) {
            return Ok(None);
        }
        if self.processor.state_store.revalidation_version()? != Some(ATOMIC_REVALIDATION_VERSION) {
            return Ok(None);
        }
        let state = self.processor.state.lock().await;
        if state.degraded || !state.live_correct || !state.has_verified_state() {
            return Ok(None);
        }
        Ok(state.materialize_context_at_block(at_block_hash, state.runtime_state(false)))
    }

    pub async fn mark_degraded_and_persist(&self, reason: &str) -> AtomicTokenResult<()> {
        let _operation_guard = self.processor.operation_lock.lock().await;
        let mut state = self.processor.state.lock().await;
        if !state.degraded {
            warn!("[{IDENT}] marking Cryptix Atomic state degraded: {reason}");
        }
        state.mark_degraded();
        self.processor.state_store.persist_runtime_flags(
            state.applied_chain_order.last().copied(),
            state.applied_chain_order.len() as u64,
            state.degraded,
            state.next_event_sequence,
        )
    }

    pub async fn get_balance(&self, asset_id: [u8; 32], owner_id: [u8; 32]) -> u128 {
        self.processor.balance(asset_id, owner_id).await
    }

    pub async fn get_nonce(&self, owner_id: [u8; 32]) -> u64 {
        self.processor.owner_nonce(owner_id).await
    }

    pub async fn get_owner_nonce(&self, owner_id: [u8; 32]) -> u64 {
        self.processor.owner_nonce(owner_id).await
    }

    pub async fn get_token_nonce(&self, owner_id: [u8; 32], asset_id: [u8; 32]) -> u64 {
        self.processor.token_nonce(owner_id, asset_id).await
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

    pub async fn get_read_context(&self, requested_at_block_hash: Option<BlockHash>) -> Option<AtomicTokenReadContext> {
        self.processor.read_context(requested_at_block_hash, self.genesis_hash).await
    }

    pub async fn get_balance_with_context(
        &self,
        asset_id: [u8; 32],
        owner_id: [u8; 32],
        requested_at_block_hash: Option<BlockHash>,
    ) -> Option<(AtomicTokenReadContext, u128)> {
        self.processor.balance_read(asset_id, owner_id, requested_at_block_hash, self.genesis_hash).await
    }

    pub async fn get_nonce_with_context(
        &self,
        key: NonceKey,
        requested_at_block_hash: Option<BlockHash>,
    ) -> Option<(AtomicTokenReadContext, u64)> {
        self.processor.nonce_read(key, requested_at_block_hash, self.genesis_hash).await
    }

    pub async fn get_anchor_count_with_context(
        &self,
        owner_id: [u8; 32],
        requested_at_block_hash: Option<BlockHash>,
    ) -> Option<(AtomicTokenReadContext, u64)> {
        self.processor.anchor_count_read(owner_id, requested_at_block_hash, self.genesis_hash).await
    }

    pub async fn get_asset_with_context(
        &self,
        asset_id: [u8; 32],
        requested_at_block_hash: Option<BlockHash>,
    ) -> Option<(AtomicTokenReadContext, Option<TokenAsset>)> {
        self.processor.asset_read(asset_id, requested_at_block_hash, self.genesis_hash).await
    }

    pub async fn get_op_status_with_context(
        &self,
        txid: BlockHash,
        requested_at_block_hash: Option<BlockHash>,
    ) -> Option<(AtomicTokenReadContext, Option<ProcessedOp>)> {
        self.processor.op_status_read(txid, requested_at_block_hash, self.genesis_hash).await
    }

    pub async fn get_assets_page(
        &self,
        offset: usize,
        limit: usize,
        query: String,
        requested_at_block_hash: Option<BlockHash>,
    ) -> Option<(AtomicTokenReadContext, Vec<TokenAsset>, u64)> {
        self.processor.assets_page(offset, limit, query, requested_at_block_hash, self.genesis_hash).await
    }

    pub async fn get_simulation_view(
        &self,
        owner_id: [u8; 32],
        op: &TokenOp,
        requested_at_block_hash: Option<BlockHash>,
    ) -> Option<AtomicTokenReadView> {
        self.processor.simulation_view(owner_id, op, requested_at_block_hash, self.genesis_hash).await
    }

    pub async fn revalidate_retained_state_once(&self) -> AtomicTokenResult<bool> {
        {
            let state = self.processor.state.lock().await;
            if !state.degraded && state.live_correct && state.has_verified_state() {
                info!("[{IDENT}] Cryptix Atomic retained-chain revalidation skipped: local state is already healthy");
                return Ok(false);
            }
        }
        self.revalidate_loaded_state_once_per_process(false).await
    }

    pub async fn revalidate_retained_state_for_audit_once(&self) -> AtomicTokenResult<bool> {
        if self.processor.bootstrap_in_progress.load(Ordering::SeqCst) {
            return Ok(false);
        }
        self.revalidate_loaded_state_once_per_process(true).await
    }

    pub async fn repair_from_local_selected_chain_once(&self) -> AtomicTokenResult<bool> {
        if self.processor.bootstrap_in_progress.load(Ordering::SeqCst) {
            return Ok(false);
        }
        let has_verified_state = { self.processor.state.lock().await.has_verified_state() };
        if has_verified_state {
            self.revalidate_retained_state_once().await
        } else {
            self.backfill_empty_state_from_local_selected_chain().await
        }
    }

    fn prune_stale_state_hash_checkpoints(&self, state: &mut AtomicTokenState) -> AtomicTokenResult<usize> {
        let retained_hashes = state.applied_chain_order.iter().copied().collect::<HashSet<_>>();
        state.state_hash_by_block.retain(|block_hash, _| retained_hashes.contains(block_hash));
        self.processor.state_store.prune_state_hashes_except(&retained_hashes)
    }

    async fn accept_persisted_state_fast_path(&self) -> AtomicTokenResult<bool> {
        if self.processor.state_store.revalidation_version()? != Some(ATOMIC_REVALIDATION_VERSION) {
            return Ok(false);
        }
        let current_root = match self.processor.state_store.current_root()? {
            Some(root) => root,
            None => return Ok(false),
        };

        let mut state = self.processor.state.lock().await;
        if state.degraded || !state.has_verified_state() {
            return Ok(false);
        }
        if state.applied_chain_order.iter().any(|block_hash| !state.state_hash_by_block.contains_key(block_hash)) {
            return Ok(false);
        }
        let Some(last_applied) = state.applied_chain_order.last().copied() else {
            return Ok(false);
        };
        let Some(last_retained_hash) = state.state_hash_by_block.get(&last_applied).copied() else {
            return Ok(false);
        };
        if current_root != last_retained_hash {
            return Ok(false);
        }

        state.live_correct = true;
        let pruned_state_hashes = if state.state_hash_by_block.len() > state.applied_chain_order.len() {
            self.prune_stale_state_hash_checkpoints(&mut state)?
        } else {
            0
        };
        if pruned_state_hashes > 0 {
            info!("[{IDENT}] Cryptix Atomic startup fast path pruned {} stale retained state hash checkpoint(s)", pruned_state_hashes);
        }
        info!("[{IDENT}] Cryptix Atomic startup state revalidation skipped: persisted V2 root matches retained tip {}", last_applied);
        drop(state);
        self.processor.notify_state_progress();
        Ok(true)
    }

    async fn catch_up_loaded_state_to_consensus_sink(&self) -> AtomicTokenResult<bool> {
        let last_applied = { self.processor.state.lock().await.applied_chain_order.last().copied() };
        let Some(last_applied) = last_applied else {
            return Ok(false);
        };

        let consensus = self.processor.consensus_manager.consensus();
        let session = consensus.session().await;
        let sink = session.async_get_sink().await;
        if last_applied == sink {
            return Ok(false);
        }

        let replay_chain = session.async_get_virtual_chain_from_block(last_applied, None).await?;
        if replay_chain.added.is_empty() && replay_chain.removed.is_empty() {
            return Ok(false);
        }
        info!(
            "[{IDENT}] Cryptix Atomic startup catch-up from retained tip {} to consensus sink {}: +{} / -{} block(s)",
            last_applied,
            sink,
            replay_chain.added.len(),
            replay_chain.removed.len()
        );
        let acceptance_data = session.async_get_blocks_acceptance_data(replay_chain.added.clone(), None).await?;
        if acceptance_data.len() != replay_chain.added.len() {
            return Err(AtomicTokenError::Processing(format!(
                "startup Atomic catch-up failed: acceptance-data length mismatch ({} != {})",
                acceptance_data.len(),
                replay_chain.added.len()
            )));
        }
        let notification = VirtualChainChangedNotification::new(
            Arc::new(replay_chain.added.clone()),
            Arc::new(replay_chain.removed.clone()),
            Arc::new(acceptance_data),
        );
        self.processor.process(ConsensusNotification::VirtualChainChanged(notification)).await?;
        info!("[{IDENT}] Cryptix Atomic startup catch-up completed successfully");
        Ok(true)
    }

    pub async fn get_indexed_balances_by_owner(
        &self,
        owner_id: [u8; 32],
        include_assets: bool,
        requested_at_block_hash: Option<BlockHash>,
    ) -> Option<(AtomicTokenReadContext, Vec<TokenOwnerBalanceEntry>)> {
        self.processor.indexed_balances_by_owner(owner_id, include_assets, requested_at_block_hash, self.genesis_hash).await
    }

    pub async fn get_indexed_holders_by_asset(
        &self,
        asset_id: [u8; 32],
        requested_at_block_hash: Option<BlockHash>,
    ) -> Option<(AtomicTokenReadContext, Vec<TokenHolderEntry>)> {
        self.processor.indexed_holders_by_asset(asset_id, requested_at_block_hash, self.genesis_hash).await
    }

    pub async fn get_indexed_liquidity_holders(
        &self,
        asset_id: [u8; 32],
        requested_at_block_hash: Option<BlockHash>,
    ) -> Option<(AtomicTokenReadContext, Option<TokenAsset>, Vec<TokenHolderEntry>, HashMap<[u8; 32], LiquidityHolderAddressState>)>
    {
        self.processor.indexed_liquidity_holders(asset_id, requested_at_block_hash, self.genesis_hash).await
    }

    async fn revalidate_loaded_state(&self, force_healthy_revalidation: bool) -> AtomicTokenResult<bool> {
        let _operation_guard = self.processor.operation_lock.lock().await;
        let _bootstrap_progress_guard = BootstrapProgressGuard::new(&self.processor.bootstrap_in_progress);
        if self.retained_revalidation_failed.load(Ordering::SeqCst) {
            return Err(AtomicTokenError::Processing(
                "retained-chain revalidation already failed in this process; remote snapshot bootstrap is required".to_string(),
            ));
        }

        let loaded_state = {
            let state = self.processor.state.lock().await;
            if !state.has_verified_state() {
                return Ok(false);
            }
            if !force_healthy_revalidation && !state.degraded && state.live_correct {
                info!("[{IDENT}] Cryptix Atomic startup state revalidation skipped: local state became healthy");
                return Ok(false);
            }
            info!(
                "[{IDENT}] Cryptix Atomic startup state revalidation starting: retained_blocks={}, degraded={}, live_correct={}",
                state.applied_chain_order.len(),
                state.degraded,
                state.live_correct
            );
            state.clone()
        };

        let first_replayable_block_hash = loaded_state.first_replayable_block_hash().ok_or_else(|| {
            AtomicTokenError::Processing(
                "startup state revalidation failed: no contiguous retained replay journal window is available".to_string(),
            )
        })?;
        let first_replayable_index =
            loaded_state.applied_chain_order.iter().position(|hash| *hash == first_replayable_block_hash).ok_or_else(|| {
                AtomicTokenError::Processing("startup state revalidation failed: replay root not retained".to_string())
            })?;
        let expected_chain = loaded_state.applied_chain_order[first_replayable_index..].to_vec();
        let expected_hashes = loaded_state.state_hash_by_block.clone();
        info!(
            "[{IDENT}] Cryptix Atomic startup state revalidation replay window: first_replayable={}, retained_replay_blocks={}",
            first_replayable_block_hash,
            expected_chain.len()
        );

        let consensus = self.processor.consensus_manager.consensus();
        let session = consensus.session().await;
        let sink = session.async_get_sink().await;
        let first_replayable_parent = session.async_get_ghostdag_data(first_replayable_block_hash).await?.selected_parent;

        if !session.async_is_chain_ancestor_of(first_replayable_parent, sink).await? {
            return Err(AtomicTokenError::Processing(format!(
                "startup state revalidation failed: retained replay root parent `{first_replayable_parent}` is not on the current canonical chain"
            )));
        }

        let replay_chain = session.async_get_virtual_chain_from_block(first_replayable_parent, None).await?;
        if !replay_chain.removed.is_empty() {
            return Err(AtomicTokenError::Processing(
                "startup state revalidation failed: expected empty removed chain from retained replay root parent".to_string(),
            ));
        }
        if replay_chain.added.first().copied() != Some(first_replayable_block_hash) {
            return Err(AtomicTokenError::Processing(format!(
                "startup state revalidation failed: canonical replay path does not start at retained replay root `{first_replayable_block_hash}`"
            )));
        }
        let matching_prefix_len =
            expected_chain.iter().zip(replay_chain.added.iter()).take_while(|(expected, actual)| expected == actual).count();
        if matching_prefix_len == 0 {
            return Err(AtomicTokenError::Processing(
                "startup state revalidation failed: canonical replay path has no retained prefix match".to_string(),
            ));
        }
        let retained_path_diverged = matching_prefix_len < expected_chain.len();
        if retained_path_diverged {
            let diverged_block = expected_chain[matching_prefix_len];
            warn!(
                "[{IDENT}] Cryptix Atomic startup state revalidation retained path diverged before block {}; replaying current canonical path from last verified prefix",
                diverged_block
            );
        }
        let replay_added = replay_chain.added.clone();
        let replay_extends_loaded_chain = replay_added.len() != expected_chain.len();
        info!(
            "[{IDENT}] Cryptix Atomic startup state revalidation canonical replay path resolved: {} block(s), retained_prefix={} block(s), sink={}",
            replay_added.len(),
            matching_prefix_len,
            sink
        );

        info!("[{IDENT}] Cryptix Atomic startup state revalidation loading acceptance data for {} block(s)", replay_added.len());
        let acceptance_data = session.async_get_blocks_acceptance_data(replay_added.clone(), None).await?;
        if acceptance_data.len() != replay_added.len() {
            return Err(AtomicTokenError::Processing(format!(
                "startup state revalidation failed: acceptance-data length mismatch ({} != {})",
                acceptance_data.len(),
                replay_added.len()
            )));
        }
        info!("[{IDENT}] Cryptix Atomic startup state revalidation loaded acceptance data for {} block(s)", acceptance_data.len());
        let auth_inputs = self.processor.collect_auth_inputs_for_added_blocks(&replay_added).await?;

        let temp_state_dir = unique_atomic_temp_dir(&self.atomic_data_dir, "startup-revalidation")?;
        let _temp_state_cleanup = RemoveDirOnDrop::new(temp_state_dir.clone());
        let temp_state_store = if first_replayable_index == 0 {
            Arc::new(AtomicStorageV2::open(&temp_state_dir, self.protocol_version, self.network_id.clone(), self.genesis_hash)?)
        } else {
            self.processor.state_store.checkpoint_to(&temp_state_dir)?;
            Arc::new(AtomicStorageV2::open(&temp_state_dir, self.protocol_version, self.network_id.clone(), self.genesis_hash)?)
        };
        let mut staged_state = loaded_state.clone();
        if first_replayable_index == 0 {
            staged_state.reset_to_empty_replay_state(temp_state_store.clone());
            info!("[{IDENT}] Cryptix Atomic startup state revalidation replay starts at retained root; using clean V2 replay store");
        } else {
            staged_state.attach_state_store(temp_state_store.clone());
            staged_state.degraded = false;
            staged_state.live_correct = false;
            info!(
                "[{IDENT}] Cryptix Atomic startup state revalidation rolling back retained replay window to parent of {}",
                first_replayable_block_hash
            );
            staged_state.rollback_snapshot_window_to_parent_persisted(first_replayable_block_hash)?;
        }

        let replay_notification =
            VirtualChainChangedNotification::new(Arc::new(replay_added.clone()), Arc::new(Vec::new()), Arc::new(acceptance_data));
        info!("[{IDENT}] Cryptix Atomic startup state revalidation replaying {} block(s)", replay_added.len());
        staged_state.apply_virtual_chain_change(&replay_notification, &auth_inputs, &self.processor.consensus_manager).await?;
        info!("[{IDENT}] Cryptix Atomic startup state revalidation replay completed; verifying retained state hashes");

        let final_replayed_block_hash = expected_chain.get(matching_prefix_len - 1).copied().ok_or_else(|| {
            AtomicTokenError::Processing("startup state revalidation failed: empty matching replay prefix".to_string())
        })?;
        let final_expected_state_hash = expected_hashes.get(&final_replayed_block_hash).copied().ok_or_else(|| {
            AtomicTokenError::Processing(format!(
                "startup state revalidation failed: missing persisted state hash for retained block `{final_replayed_block_hash}`"
            ))
        })?;
        let final_replayed_state_hash = staged_state.get_state_hash_at_block(final_replayed_block_hash).ok_or_else(|| {
            AtomicTokenError::Processing(format!(
                "startup state revalidation failed: replay did not reproduce retained block `{final_replayed_block_hash}`"
            ))
        })?;
        let mut refreshed_retained_hashes = Vec::new();
        if final_replayed_state_hash != final_expected_state_hash {
            warn!(
                "[{IDENT}] Cryptix Atomic startup state revalidation repaired stale final retained checkpoint {}; stored={}, replayed={}",
                final_replayed_block_hash,
                short_hex_for_log(&final_expected_state_hash),
                short_hex_for_log(&final_replayed_state_hash)
            );
            refreshed_retained_hashes.reserve(matching_prefix_len);
            for block_hash in expected_chain.iter().take(matching_prefix_len).copied() {
                let replayed_state_hash = staged_state.get_state_hash_at_block(block_hash).ok_or_else(|| {
                    AtomicTokenError::Processing(format!(
                        "startup state revalidation failed: replay did not reproduce retained block `{block_hash}`"
                    ))
                })?;
                refreshed_retained_hashes.push((block_hash, replayed_state_hash));
            }
        } else {
            let mut stale_checkpoint_count = 0usize;
            let mut first_stale_checkpoint = None;
            let mut last_hash_check_log = Instant::now();
            for (idx, block_hash) in expected_chain.iter().take(matching_prefix_len).copied().enumerate() {
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
                    stale_checkpoint_count = stale_checkpoint_count.saturating_add(1);
                    first_stale_checkpoint.get_or_insert((block_hash, expected_state_hash, replayed_state_hash));
                }
                if matching_prefix_len >= 1024 && last_hash_check_log.elapsed() >= ATOMIC_LONG_OPERATION_LOG_INTERVAL {
                    info!(
                        "[{IDENT}] Cryptix Atomic startup state revalidation hash-check progress: {}/{} checkpoint(s), stale={}",
                        idx.saturating_add(1),
                        matching_prefix_len,
                        stale_checkpoint_count
                    );
                    last_hash_check_log = Instant::now();
                }
            }
            if let Some((block_hash, stored_hash, replayed_hash)) = first_stale_checkpoint {
                warn!(
                    "[{IDENT}] Cryptix Atomic startup state revalidation found {} stale retained checkpoint hash(es); final retained checkpoint {} matched deterministic replay, so refreshing checkpoint cache. first_mismatch={}, stored={}, replayed={}",
                    stale_checkpoint_count,
                    final_replayed_block_hash,
                    block_hash,
                    short_hex_for_log(&stored_hash),
                    short_hex_for_log(&replayed_hash)
                );
                refreshed_retained_hashes.reserve(matching_prefix_len);
                for block_hash in expected_chain.iter().take(matching_prefix_len).copied() {
                    let replayed_state_hash = staged_state.get_state_hash_at_block(block_hash).ok_or_else(|| {
                        AtomicTokenError::Processing(format!(
                            "startup state revalidation failed: replay did not reproduce retained block `{block_hash}`"
                        ))
                    })?;
                    refreshed_retained_hashes.push((block_hash, replayed_state_hash));
                }
            } else {
                info!(
                    "[{IDENT}] Cryptix Atomic startup state revalidation verified {} retained state hash checkpoint(s)",
                    matching_prefix_len
                );
            }
            info!(
                "[{IDENT}] Cryptix Atomic startup state revalidation verified final retained checkpoint {}",
                final_replayed_block_hash
            );
        }

        let mut state = self.processor.state.lock().await;
        let active_state_needs_repair = loaded_state.degraded
            || retained_path_diverged
            || replay_extends_loaded_chain
            || final_replayed_state_hash != final_expected_state_hash;
        if active_state_needs_repair {
            staged_state.degraded = false;
            staged_state.live_correct = true;
            if let Some(pruned) = staged_state.prune_history_with_details(self.max_retained_blocks) {
                temp_state_store.prune_history(
                    &pruned.pruned_hashes,
                    &staged_state.applied_chain_order,
                    pruned.last_pruned_event_sequence,
                )?;
                if pruned.pruned_processed_ops {
                    info!("[{IDENT}] Cryptix Atomic pruned processed-op guard entries after startup state repair");
                }
            }
            let repaired_state = copy_snapshot_store_into_active(&temp_state_store, self.processor.state_store.clone(), staged_state)?;
            *state = repaired_state;
            info!(
                "[{IDENT}] Cryptix Atomic startup state revalidation repaired active V2 store from deterministic replay: diverged={}, extended={}, stale_final_hash={}",
                retained_path_diverged,
                replay_extends_loaded_chain,
                final_replayed_state_hash != final_expected_state_hash
            );
        }
        if !refreshed_retained_hashes.is_empty() {
            let retained_hashes = state.applied_chain_order.iter().copied().collect::<HashSet<_>>();
            refreshed_retained_hashes.retain(|(block_hash, _)| retained_hashes.contains(block_hash));
        }
        if !refreshed_retained_hashes.is_empty() {
            let refreshed_count = self.processor.state_store.replace_state_hashes(refreshed_retained_hashes.iter().copied())?;
            for (block_hash, state_hash) in refreshed_retained_hashes {
                state.state_hash_by_block.insert(block_hash, state_hash);
            }
            info!(
                "[{IDENT}] Cryptix Atomic startup state revalidation refreshed {} retained checkpoint hash(es) from deterministic replay",
                refreshed_count
            );
        }
        if let Some(pruned) = state.prune_history_with_details(self.max_retained_blocks) {
            self.processor.state_store.prune_history(
                &pruned.pruned_hashes,
                &state.applied_chain_order,
                pruned.last_pruned_event_sequence,
            )?;
            if pruned.pruned_processed_ops {
                info!("[{IDENT}] Cryptix Atomic pruned processed-op guard entries after startup state revalidation");
            }
        }
        let pruned_state_hashes = if state.state_hash_by_block.len() > state.applied_chain_order.len() {
            self.prune_stale_state_hash_checkpoints(&mut state)?
        } else {
            0
        };
        if pruned_state_hashes > 0 {
            info!("[{IDENT}] Cryptix Atomic startup state revalidation pruned {} stale state hash checkpoint(s)", pruned_state_hashes);
        }
        state.degraded = false;
        state.live_correct = true;

        self.processor.state_store.persist_runtime_flags(
            state.applied_chain_order.last().copied(),
            state.applied_chain_order.len() as u64,
            state.degraded,
            state.next_event_sequence,
        )?;
        self.processor.state_store.persist_revalidation_version(ATOMIC_REVALIDATION_VERSION)?;
        drop(state);
        self.processor.notify_state_progress();
        Ok(true)
    }

    async fn revalidate_loaded_state_once_per_process(&self, force_healthy_revalidation: bool) -> AtomicTokenResult<bool> {
        if self.retained_revalidation_failed.load(Ordering::SeqCst) {
            return Err(AtomicTokenError::Processing(
                "retained-chain revalidation already failed in this process; remote snapshot bootstrap is required".to_string(),
            ));
        }

        match self.revalidate_loaded_state(force_healthy_revalidation).await {
            Ok(true) => {
                self.retained_revalidation_failed.store(false, Ordering::SeqCst);
                Ok(true)
            }
            Ok(false) => Ok(false),
            Err(err) => {
                self.retained_revalidation_failed.store(true, Ordering::SeqCst);
                Err(err)
            }
        }
    }

    async fn backfill_empty_state_from_local_selected_chain(&self) -> AtomicTokenResult<bool> {
        {
            let state = self.processor.state.lock().await;
            if state.has_verified_state() {
                return Ok(false);
            }
        }

        let consensus = self.processor.consensus_manager.consensus();
        let session = consensus.session().await;
        let sink = session.async_get_sink().await;
        let sink_header = session.async_get_header(sink).await?;
        if sink_header.daa_score < self.payload_hf_activation_daa_score {
            return Ok(false);
        }

        let replay_chain = session.async_get_virtual_chain_from_block(self.genesis_hash, None).await?;
        if replay_chain.added.is_empty() {
            return Ok(false);
        }

        info!(
            "[{IDENT}] Cryptix Atomic has no retained V2 state; backfilling {} selected-chain block(s) from local block data to sink {}",
            replay_chain.added.len(),
            sink
        );
        info!("[{IDENT}] Cryptix Atomic local backfill loading acceptance data for {} block(s)", replay_chain.added.len());
        let acceptance_data = session.async_get_blocks_acceptance_data(replay_chain.added.clone(), None).await?;
        if acceptance_data.len() != replay_chain.added.len() {
            return Err(AtomicTokenError::Processing(format!(
                "local Atomic backfill failed: acceptance-data length mismatch ({} != {})",
                acceptance_data.len(),
                replay_chain.added.len()
            )));
        }
        let auth_inputs = self.processor.collect_auth_inputs_for_added_blocks(&replay_chain.added).await?;
        let notification = VirtualChainChangedNotification::new(
            Arc::new(replay_chain.added.clone()),
            Arc::new(Vec::new()),
            Arc::new(acceptance_data),
        );

        self.processor.set_bootstrap_in_progress(true);
        let result = async {
            let mut state = self.processor.state.lock().await;
            if state.has_verified_state() {
                return Ok(false);
            }
            state.apply_virtual_chain_change(&notification, &auth_inputs, &self.processor.consensus_manager).await?;
            if let Some(pruned) = state.prune_history_with_details(self.max_retained_blocks) {
                self.processor.state_store.prune_history(
                    &pruned.pruned_hashes,
                    &state.applied_chain_order,
                    pruned.last_pruned_event_sequence,
                )?;
                if pruned.pruned_processed_ops {
                    info!("[{IDENT}] Cryptix Atomic pruned processed-op guard entries after local backfill");
                }
            }
            self.processor.state_store.persist_runtime_flags(
                state.applied_chain_order.last().copied(),
                state.applied_chain_order.len() as u64,
                state.degraded,
                state.next_event_sequence,
            )?;
            self.processor.state_store.persist_revalidation_version(ATOMIC_REVALIDATION_VERSION)?;
            Ok(true)
        }
        .await;
        self.processor.set_bootstrap_in_progress(false);

        if result.as_ref().copied().unwrap_or(false) {
            let state = self.processor.state.lock().await;
            let retained_blocks = state.applied_chain_order.len();
            let footprint = state.footprint();
            let state_store_bytes = self.processor.state_store.approximate_size_bytes();
            drop(state);
            let health = self.processor.health().await;
            self.processor.maybe_log_progress(
                notification.added_chain_block_hashes.len(),
                0,
                retained_blocks,
                health,
                footprint,
                state_store_bytes,
            );
            info!("[{IDENT}] Cryptix Atomic local selected-chain backfill completed successfully");
        }
        result
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
        let finality_distance = sink_header.blue_score.saturating_sub(fp_header.blue_score);
        if finality_distance < self.expected_finality_depth {
            return Err(AtomicTokenError::Processing(format!(
                "snapshot export failed: finality depth sanity check failed (distance {}, required {}, sink {}, finality point {})",
                finality_distance, self.expected_finality_depth, sink, fp
            )));
        }

        Ok((fp, fp_header.daa_score))
    }

    async fn current_p2p_audit_anchor(&self) -> AtomicTokenResult<(BlockHash, u64)> {
        let (mut anchor_hash, fp_daa_score) = self.current_snapshot_anchor().await?;
        let target_daa_score = fp_daa_score.saturating_sub(P2P_AUDIT_RENDEZVOUS_DAA_LAG);

        let consensus = self.processor.consensus_manager.consensus();
        let session = consensus.session().await;
        let mut anchor_header = session.async_get_header(anchor_hash).await?;
        while anchor_header.daa_score > target_daa_score && anchor_hash != self.genesis_hash {
            let ghostdag = session.async_get_ghostdag_data(anchor_hash).await?;
            let selected_parent = ghostdag.selected_parent;
            if selected_parent == anchor_hash {
                break;
            }
            anchor_hash = selected_parent;
            anchor_header = session.async_get_header(anchor_hash).await?;
        }

        Ok((anchor_hash, anchor_header.daa_score))
    }

    fn prune_bootstrap_snapshot_store(&self) -> AtomicTokenResult<()> {
        prune_snapshot_catalog_entries(
            &self.snapshot_store_dir,
            self.protocol_version,
            &self.network_id,
            BOOTSTRAP_STORE_MAX_SNAPSHOTS_PER_NETWORK,
        )
    }

    async fn refresh_current_bootstrap_snapshot(&self) -> AtomicTokenResult<()> {
        let (anchor_hash, _anchor_daa_score) = self.current_snapshot_anchor().await?;
        let anchor_hash_bytes = hash_to_array(anchor_hash);
        let already_present = {
            let state = self.processor.state.lock().await;
            let local_anchor_state_hash = state.get_state_hash_at_block(anchor_hash);
            list_snapshot_catalog(&self.snapshot_store_dir)?.into_iter().any(|entry| {
                entry.manifest.protocol_version == self.protocol_version
                    && entry.manifest.network_id == self.network_id
                    && entry.manifest.at_block_hash == anchor_hash_bytes
                    && Some(entry.manifest.state_hash_at_fp) == local_anchor_state_hash
                    && cached_snapshot_parent_checkpoint_matches_current_state(&entry, &state)
            })
        };
        if already_present {
            let _ = self.prune_bootstrap_snapshot_store();
            return Ok(());
        }

        let snapshot_path = self.snapshot_store_dir.join(format!("atomic-snapshot-{}.bin", anchor_hash));
        self.export_snapshot_to_file(snapshot_path).await?;
        let _ = self.prune_bootstrap_snapshot_store();
        Ok(())
    }

    async fn ensure_current_bootstrap_snapshot(&self) -> AtomicTokenResult<()> {
        let _refresh_guard = self.snapshot_refresh_lock.lock().await;
        self.refresh_current_bootstrap_snapshot().await
    }

    fn bootstrap_sources_from_catalog(&self) -> AtomicTokenResult<Vec<ScBootstrapSource>> {
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

    pub async fn get_sc_bootstrap_sources(&self) -> AtomicTokenResult<Vec<ScBootstrapSource>> {
        self.ensure_bootstrap_serving_ready().await?;

        let mut sources = self.bootstrap_sources_from_catalog()?;
        let refresh_error = if sources.is_empty() {
            let refresh_error = self.ensure_current_bootstrap_snapshot().await.err();
            if refresh_error.is_none() {
                sources = self.bootstrap_sources_from_catalog()?;
            }
            refresh_error
        } else {
            None
        };
        if sources.is_empty() {
            if let Some(err) = refresh_error {
                let err = err.to_string();
                if err.contains("finality depth sanity check failed") {
                    debug!("[{IDENT}] Atomic bootstrap snapshot not finality-safe yet: {err}");
                } else {
                    info!("[{IDENT}] Atomic bootstrap snapshot currently unavailable: {err}");
                }
            }
        }
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

        let temp_state_dir = unique_atomic_temp_dir(&self.atomic_data_dir, "snapshot-export")?;
        let _temp_state_cleanup = RemoveDirOnDrop::new(temp_state_dir.clone());
        self.processor.state_store.checkpoint_to(&temp_state_dir)?;
        let temp_state_store =
            Arc::new(AtomicStorageV2::open(&temp_state_dir, self.protocol_version, self.network_id.clone(), self.genesis_hash)?);
        let mut state = temp_state_store.load_runtime_state()?.ok_or_else(|| {
            AtomicTokenError::Processing("snapshot export failed: no persisted Atomic V2 state is available".to_string())
        })?;
        state.attach_state_store(temp_state_store.clone());
        state.rollback_to_block_persisted(anchor_hash)?;

        let anchor_index = state.applied_chain_order.iter().position(|hash| *hash == anchor_hash).ok_or_else(|| {
            AtomicTokenError::Processing("snapshot export failed: snapshot anchor not found in local Atomic chain order".to_string())
        })?;
        let start_index = anchor_index.saturating_sub(self.replay_overlap.saturating_sub(1));
        let window_blocks = state.applied_chain_order[start_index..=anchor_index].to_vec();
        let window_start_block_hash = *window_blocks
            .first()
            .ok_or_else(|| AtomicTokenError::Processing("snapshot export failed: empty replay window".to_string()))?;
        let window_start_parent_block_hash =
            if start_index > 0 { state.applied_chain_order[start_index - 1] } else { self.genesis_hash };
        let state_hash_at_window_start_parent =
            if start_index > 0 { state.state_hash_by_block.get(&window_start_parent_block_hash).copied() } else { None };
        let state_hash_at_fp = state.compute_state_hash();
        let mut journals_in_window = Vec::with_capacity(window_blocks.len());
        for block_hash in window_blocks.iter().copied() {
            let journal = state.block_journals.get(&block_hash).cloned().ok_or_else(|| {
                AtomicTokenError::Processing(format!("snapshot export failed: missing journal for replay block `{block_hash}`"))
            })?;
            journals_in_window.push((block_hash, journal));
        }
        let counts = temp_state_store.snapshot_counts()?;
        let header = SnapshotFileHeaderV2 {
            schema_version: crate::state::SNAPSHOT_SCHEMA_VERSION,
            protocol_version: self.protocol_version,
            network_id: self.network_id.clone(),
            at_block_hash: anchor_hash,
            at_daa_score: anchor_daa_score,
            state_hash_at_fp,
            state_hash_at_window_start_parent,
            window_start_block_hash,
            window_start_parent_block_hash,
            window_end_block_hash: anchor_hash,
            next_event_sequence: state.next_event_sequence,
            counts,
        };

        let snapshot_path = path.as_ref();
        write_snapshot_file_from_store(snapshot_path, &header, &temp_state_store)?;
        let replay_path = snapshot_replay_path(snapshot_path);
        write_replay_window_transfer_parts(
            header.protocol_version,
            &header.network_id,
            header.window_start_block_hash,
            header.window_end_block_hash,
            &journals_in_window,
            &replay_path,
        )?;

        let manifest = build_snapshot_manifest_from_files_v2(snapshot_path, &replay_path, &header)?;
        let manifest_bytes =
            borsh::to_vec(&manifest).map_err(|e| AtomicTokenError::Processing(format!("snapshot manifest encode failed: {e}")))?;
        std::fs::write(snapshot_manifest_path(snapshot_path), manifest_bytes)
            .map_err(|e| AtomicTokenError::Processing(format!("snapshot manifest write failed: {e}")))?;

        // Keep a bootstrap-store copy so peers can serve this snapshot via getSc* APIs.
        let store_snapshot_path = self.snapshot_store_dir.join(&manifest.snapshot_file_name);
        if store_snapshot_path != snapshot_path {
            std::fs::copy(snapshot_path, &store_snapshot_path)
                .map_err(|e| AtomicTokenError::Processing(format!("snapshot store copy failed: {e}")))?;
            let store_replay_path = snapshot_replay_path(&store_snapshot_path);
            std::fs::copy(&replay_path, &store_replay_path)
                .map_err(|e| AtomicTokenError::Processing(format!("snapshot store replay copy failed: {e}")))?;
            let store_manifest = build_snapshot_manifest_from_files_v2(&store_snapshot_path, &store_replay_path, &header)?;
            let store_manifest_bytes = borsh::to_vec(&store_manifest)
                .map_err(|e| AtomicTokenError::Processing(format!("snapshot store manifest encode failed: {e}")))?;
            std::fs::write(snapshot_manifest_path(&store_snapshot_path), store_manifest_bytes)
                .map_err(|e| AtomicTokenError::Processing(format!("snapshot store manifest write failed: {e}")))?;
        }
        drop(state);
        drop(temp_state_store);
        let _ = self.prune_bootstrap_snapshot_store();
        Ok(())
    }

    pub async fn import_snapshot_from_file<P: AsRef<Path>>(&self, path: P) -> AtomicTokenResult<()> {
        let _operation_guard = self.processor.operation_lock.lock().await;
        self.processor.set_bootstrap_in_progress(true);
        let import_result: AtomicTokenResult<()> = async {
            let path_ref = path.as_ref();
            let snapshot_size = std::fs::metadata(path_ref)
                .map_err(|e| AtomicTokenError::Processing(format!("snapshot metadata read failed: {e}")))?
                .len();
            validate_snapshot_blob_size_limits(snapshot_size, 0, "snapshot import")?;
            info!(
                "[{IDENT}] Atomic snapshot import verifying manifest and snapshot file: path={}, bytes={}",
                path_ref.display(),
                snapshot_size
            );
            let validated_snapshot = validate_snapshot_manifest_and_decode(path_ref, self.protocol_version, &self.network_id)?;
            let snapshot_header = validated_snapshot.header.clone();
            let snapshot_at_block_hash = snapshot_header.at_block_hash;
            let snapshot_state_hash_at_fp = snapshot_header.state_hash_at_fp;
            let snapshot_state_hash_at_window_start_parent = snapshot_header.state_hash_at_window_start_parent;
            let snapshot_window_start_block_hash = snapshot_header.window_start_block_hash;
            let snapshot_window_start_parent_hash = snapshot_header.window_start_parent_block_hash;
            info!(
                "[{IDENT}] Atomic snapshot import decoded: anchor={}, window_start={}, parent={}",
                snapshot_at_block_hash, snapshot_window_start_block_hash, snapshot_window_start_parent_hash
            );

            let consensus = self.processor.consensus_manager.consensus();
            let session = consensus.session().await;
            let sink = session.async_get_sink().await;
            let fp = session.async_finality_point().await;
            let is_ancestor = session.async_is_chain_ancestor_of(snapshot_at_block_hash, sink).await?;
            if !is_ancestor {
                return Err(AtomicTokenError::Processing(
                    "snapshot import failed: snapshot at_block_hash is not ancestor of current sink".to_string(),
                ));
            }
            let sink_header = session.async_get_header(sink).await?;
            if !self.unsafe_skip_snapshot_finality_check {
                let finalized_by_current_fp = session.async_is_chain_ancestor_of(snapshot_at_block_hash, fp).await?;
                if !finalized_by_current_fp {
                    return Err(AtomicTokenError::Processing(format!(
                        "snapshot import failed: at_block_hash `{}` is not finalized by current finality point `{}`",
                        snapshot_at_block_hash, fp
                    )));
                }
                let fp_header = session.async_get_header(fp).await?;
                if sink_header.blue_score.saturating_sub(fp_header.blue_score) < self.expected_finality_depth {
                    return Err(AtomicTokenError::Processing(
                        "snapshot import failed: finality depth sanity check failed".to_string(),
                    ));
                }
            }

            let replay_chain = session.async_get_virtual_chain_from_block(snapshot_window_start_parent_hash, None).await?;
            if !replay_chain.removed.is_empty() {
                return Err(AtomicTokenError::Processing(
                    "snapshot import failed: expected empty removed chain for replay path".to_string(),
                ));
            }

            if replay_chain.added.first().copied().map(|first| first != snapshot_window_start_block_hash).unwrap_or(true) {
                return Err(AtomicTokenError::Processing(
                    "snapshot import failed: replay path does not start with snapshot window_start_block_hash".to_string(),
                ));
            }
            let replay_total = replay_chain.added.len();
            info!(
                "[{IDENT}] Atomic snapshot import replay path ready: {} block(s) from {} to current sink {}",
                replay_total, snapshot_window_start_block_hash, sink
            );

            let acceptance_data = session.async_get_blocks_acceptance_data(replay_chain.added.clone(), None).await?;
            if acceptance_data.len() != replay_chain.added.len() {
                return Err(AtomicTokenError::Processing(format!(
                    "snapshot import failed: acceptance data count mismatch ({} != {})",
                    acceptance_data.len(),
                    replay_chain.added.len()
                )));
            }

            // Stage snapshot import and deterministic replay off-line, then swap into live state only if fully verified.
            let temp_state_dir = unique_atomic_temp_dir(&self.atomic_data_dir, "snapshot-import")?;
            let _temp_state_cleanup = RemoveDirOnDrop::new(temp_state_dir.clone());
            let temp_state_store = Arc::new(AtomicStorageV2::open(
                &temp_state_dir,
                self.protocol_version,
                self.network_id.clone(),
                self.genesis_hash,
            )?);
            let mut staged_state = import_snapshot_file_into_store(path_ref, &validated_snapshot, temp_state_store.clone())?;
            staged_state.set_payload_hf_activation_daa_score(self.payload_hf_activation_daa_score);
            staged_state.rollback_snapshot_window_to_parent_persisted(snapshot_window_start_block_hash)?;
            let mut window_start_parent_hash_mismatch = false;
            if let Some(expected_hash) = snapshot_state_hash_at_window_start_parent {
                let current_hash = staged_state.compute_state_hash();
                if current_hash != expected_hash {
                    window_start_parent_hash_mismatch = true;
                    warn!(
                        "[{IDENT}] Atomic snapshot window_start parent checkpoint hash mismatch; continuing to verify replay at snapshot anchor. stored={}, replayed={}",
                        short_hex_for_log(&expected_hash),
                        short_hex_for_log(&current_hash)
                    );
                }
            }

            let mut last_import_replay_log = Instant::now();
            for (idx, (accepting_block_hash, acceptance)) in replay_chain.added.into_iter().zip(acceptance_data.into_iter()).enumerate()
            {
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

                if accepting_block_hash == snapshot_at_block_hash {
                    let current_hash = staged_state.compute_state_hash();
                    if current_hash != snapshot_state_hash_at_fp {
                        return Err(AtomicTokenError::Processing(
                            "snapshot import failed: state hash mismatch at snapshot finality point".to_string(),
                        ));
                    }
                    if window_start_parent_hash_mismatch {
                        info!(
                            "[{IDENT}] Atomic snapshot parent checkpoint mismatch ignored after deterministic replay matched snapshot anchor {}",
                            snapshot_at_block_hash
                        );
                    }
                }
                if replay_total >= 1024
                    && (last_import_replay_log.elapsed() >= ATOMIC_LONG_OPERATION_LOG_INTERVAL || idx + 1 == replay_total)
                {
                    info!(
                        "[{IDENT}] Atomic snapshot import replay progress: {}/{} block(s)",
                        idx + 1,
                        replay_total
                    );
                    last_import_replay_log = Instant::now();
                }
            }

            if let Some(pruned) = staged_state.prune_history_with_details(self.max_retained_blocks) {
                temp_state_store.prune_history(
                    &pruned.pruned_hashes,
                    &staged_state.applied_chain_order,
                    pruned.last_pruned_event_sequence,
                )?;
                if pruned.pruned_processed_ops {
                    info!("[{IDENT}] Cryptix Atomic pruned processed-op guard entries after snapshot import");
                }
            }
            staged_state.live_correct = !staged_state.degraded;
            let active_state =
                copy_snapshot_store_into_active(&temp_state_store, self.processor.state_store.clone(), staged_state)?;
            {
                let mut live_state = self.processor.state.lock().await;
                *live_state = active_state;
            }
            self.processor.state_store.persist_revalidation_version(ATOMIC_REVALIDATION_VERSION)?;
            self.processor.notify_state_progress();
            Ok(())
        }
        .await;
        self.processor.set_bootstrap_in_progress(false);

        import_result
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
            info!("[{IDENT}] Cryptix Atomic service task started");
            let startup_health = self.get_health().await;
            if startup_health.runtime_state == AtomicTokenRuntimeState::Degraded {
                info!(
                    "[{IDENT}] Cryptix Atomic startup state is degraded; deferring retained-chain revalidation to bootstrap worker so remote snapshot repair can be tried first"
                );
                self.processor.set_bootstrap_in_progress(false);
            } else {
                self.processor.set_bootstrap_in_progress(true);
                let mut local_state_ready = false;
                match self.accept_persisted_state_fast_path().await {
                    Ok(true) => {
                        local_state_ready = true;
                    }
                    Ok(false) => {
                        match self.revalidate_loaded_state_once_per_process(false).await {
                            Ok(true) => {
                                info!("[{IDENT}] Cryptix Atomic startup state revalidation completed successfully");
                                local_state_ready = true;
                            }
                            Ok(false) => match self.backfill_empty_state_from_local_selected_chain().await {
                                Ok(true) => {
                                    local_state_ready = true;
                                }
                                Ok(false) => info!(
                                    "[{IDENT}] Cryptix Atomic startup state has no retained verified chain state yet; indexing will build from local virtual-chain updates"
                                ),
                                Err(err) => {
                                    warn!("[{IDENT}] Cryptix Atomic local selected-chain backfill failed: {err}");
                                    self.processor
                                        .mark_degraded_best_effort(&format!("local selected-chain backfill failed: {err}"))
                                        .await;
                                }
                            },
                            Err(err) => {
                                warn!("[{IDENT}] Cryptix Atomic startup state revalidation failed: {err}");
                                self.processor.mark_degraded_best_effort(&format!("startup state revalidation failed: {err}")).await;
                            }
                        }
                    }
                    Err(err) => {
                        warn!("[{IDENT}] Cryptix Atomic persisted-state fast path failed: {err}");
                        self.processor.mark_degraded_best_effort(&format!("persisted-state fast path failed: {err}")).await;
                    }
                }
                if local_state_ready {
                    if let Err(err) = self.catch_up_loaded_state_to_consensus_sink().await {
                        warn!("[{IDENT}] Cryptix Atomic startup catch-up failed: {err}");
                        self.processor.mark_degraded_best_effort(&format!("startup catch-up failed: {err}")).await;
                    }
                }
                self.processor.set_bootstrap_in_progress(false);
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

#[cfg(test)]
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

#[cfg(test)]
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

fn hash_file_and_chunks(path: &Path, chunk_size: usize, label: &str) -> AtomicTokenResult<(u64, [u8; 32], Vec<[u8; 32]>)> {
    if chunk_size == 0 {
        return Err(AtomicTokenError::Processing(format!("{label} failed: chunk size must be greater than zero")));
    }
    if chunk_size > SNAPSHOT_CHUNK_SIZE_MAX {
        return Err(AtomicTokenError::Processing(format!(
            "{label} failed: chunk size `{chunk_size}` exceeds maximum `{SNAPSHOT_CHUNK_SIZE_MAX}`"
        )));
    }

    let mut file =
        File::open(path).map_err(|e| AtomicTokenError::Processing(format!("{label} failed: open `{}`: {e}", path.display())))?;
    let mut whole_hasher = Blake2bParams::new().hash_length(32).to_state();
    whole_hasher.update(SNAPSHOT_MANIFEST_DOMAIN);

    let mut buf = vec![0u8; chunk_size];
    let mut total_size = 0u64;
    let mut chunks = Vec::new();
    loop {
        let read = file
            .read(&mut buf)
            .map_err(|e| AtomicTokenError::Processing(format!("{label} failed: read `{}`: {e}", path.display())))?;
        if read == 0 {
            break;
        }
        total_size = total_size
            .checked_add(read as u64)
            .ok_or_else(|| AtomicTokenError::Processing(format!("{label} failed: file size overflow")))?;
        whole_hasher.update(&buf[..read]);
        chunks.push(hash_chunk_bytes(&buf[..read]));
    }

    let digest = whole_hasher.finalize();
    let mut whole_hash = [0u8; 32];
    whole_hash.copy_from_slice(digest.as_bytes());
    Ok((total_size, whole_hash, chunks))
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

fn write_snapshot_file_from_store(path: &Path, header: &SnapshotFileHeaderV2, store: &AtomicStorageV2) -> AtomicTokenResult<()> {
    let file = File::create(path)
        .map_err(|e| AtomicTokenError::Processing(format!("snapshot write failed: create `{}`: {e}", path.display())))?;
    let mut writer = BufWriter::new(file);
    bincode::serialize_into(&mut writer, header)
        .map_err(|e| AtomicTokenError::Processing(format!("snapshot header encode failed: {e}")))?;
    store.visit_all_state_hashes(|block_hash, state_hash| {
        bincode::serialize_into(&mut writer, &(block_hash, state_hash))
            .map_err(|e| AtomicTokenError::Processing(format!("snapshot state hash encode failed: {e}")))
    })?;
    store.visit_all_event_sequences(|block_hash, sequence| {
        bincode::serialize_into(&mut writer, &(block_hash, sequence))
            .map_err(|e| AtomicTokenError::Processing(format!("snapshot event sequence encode failed: {e}")))
    })?;
    store.visit_all_chain_order(|index, block_hash| {
        bincode::serialize_into(&mut writer, &(index, block_hash))
            .map_err(|e| AtomicTokenError::Processing(format!("snapshot chain order encode failed: {e}")))
    })?;
    store.visit_all_events(|event| {
        bincode::serialize_into(&mut writer, &event)
            .map_err(|e| AtomicTokenError::Processing(format!("snapshot event encode failed: {e}")))
    })?;
    store.visit_all_assets(|asset_id, asset| {
        bincode::serialize_into(&mut writer, &(asset_id, asset))
            .map_err(|e| AtomicTokenError::Processing(format!("snapshot asset encode failed: {e}")))
    })?;
    store.visit_all_balances(|key, amount| {
        bincode::serialize_into(&mut writer, &(key, amount))
            .map_err(|e| AtomicTokenError::Processing(format!("snapshot balance encode failed: {e}")))
    })?;
    store.visit_all_nonces(|key, nonce| {
        bincode::serialize_into(&mut writer, &(key, nonce))
            .map_err(|e| AtomicTokenError::Processing(format!("snapshot nonce encode failed: {e}")))
    })?;
    store.visit_all_anchor_counts(|owner_id, count| {
        bincode::serialize_into(&mut writer, &(owner_id, count))
            .map_err(|e| AtomicTokenError::Processing(format!("snapshot anchor count encode failed: {e}")))
    })?;
    store.visit_all_processed_ops(|txid, op| {
        bincode::serialize_into(&mut writer, &(txid, op))
            .map_err(|e| AtomicTokenError::Processing(format!("snapshot processed-op encode failed: {e}")))
    })?;
    writer.flush().map_err(|e| AtomicTokenError::Processing(format!("snapshot write failed: flush `{}`: {e}", path.display())))?;
    Ok(())
}

fn write_replay_window_transfer_parts(
    protocol_version: u16,
    network_id: &str,
    window_start_block_hash: BlockHash,
    window_end_block_hash: BlockHash,
    journals_in_window: &[(BlockHash, crate::state::BlockJournal)],
    path: &Path,
) -> AtomicTokenResult<()> {
    let file = File::create(path)
        .map_err(|e| AtomicTokenError::Processing(format!("snapshot replay write failed: create `{}`: {e}", path.display())))?;
    let mut writer = BufWriter::new(file);
    let transfer = ReplayWindowTransferV2Ref {
        protocol_version,
        network_id,
        window_start_block_hash: hash_to_array(window_start_block_hash),
        window_end_block_hash: hash_to_array(window_end_block_hash),
        journals_in_window,
    };
    bincode::serialize_into(&mut writer, &transfer)
        .map_err(|e| AtomicTokenError::Processing(format!("failed encoding replay window transfer: {e}")))?;
    writer
        .flush()
        .map_err(|e| AtomicTokenError::Processing(format!("snapshot replay write failed: flush `{}`: {e}", path.display())))?;
    Ok(())
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

fn build_snapshot_manifest_from_files_v2(
    path: &Path,
    replay_path: &Path,
    header: &SnapshotFileHeaderV2,
) -> AtomicTokenResult<SnapshotManifestV2> {
    let snapshot_file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| AtomicTokenError::Processing("snapshot export failed: invalid snapshot file name".to_string()))?
        .to_string();
    let snapshot_chunk_size = SNAPSHOT_CHUNK_SIZE_DEFAULT as u32;
    let replay_window_chunk_size = SNAPSHOT_CHUNK_SIZE_DEFAULT as u32;
    let (snapshot_file_size, snapshot_file_hash, snapshot_chunk_hashes) =
        hash_file_and_chunks(path, snapshot_chunk_size as usize, "snapshot export")?;
    let (replay_window_size, replay_window_hash, replay_window_chunk_hashes) =
        hash_file_and_chunks(replay_path, replay_window_chunk_size as usize, "snapshot replay export")?;
    validate_snapshot_blob_size_limits(snapshot_file_size, replay_window_size, "snapshot export")?;
    Ok(SnapshotManifestV2 {
        schema_version: header.schema_version,
        protocol_version: header.protocol_version,
        network_id: header.network_id.clone(),
        snapshot_file_name,
        snapshot_file_size,
        snapshot_file_hash,
        snapshot_chunk_size,
        snapshot_chunk_hashes,
        replay_window_size,
        replay_window_hash,
        replay_window_chunk_size,
        replay_window_chunk_hashes,
        at_block_hash: hash_to_array(header.at_block_hash),
        at_daa_score: header.at_daa_score,
        state_hash_at_fp: header.state_hash_at_fp,
        state_hash_at_window_start_parent: header.state_hash_at_window_start_parent,
        window_start_block_hash: hash_to_array(header.window_start_block_hash),
        window_start_parent_block_hash: hash_to_array(header.window_start_parent_block_hash),
        window_end_block_hash: hash_to_array(header.window_end_block_hash),
    })
}

#[derive(Default)]
struct SnapshotStateImportChunk {
    assets: Vec<([u8; 32], Option<TokenAsset>)>,
    balances: Vec<(BalanceKey, Option<u128>)>,
    nonces: Vec<(NonceKey, Option<u64>)>,
    anchor_counts: Vec<([u8; 32], Option<u64>)>,
    processed_ops: Vec<(BlockHash, Option<ProcessedOp>)>,
}

impl SnapshotStateImportChunk {
    fn len(&self) -> usize {
        self.assets.len() + self.balances.len() + self.nonces.len() + self.anchor_counts.len() + self.processed_ops.len()
    }

    fn flush_if_full(&mut self, store: &AtomicStorageV2) -> AtomicTokenResult<()> {
        if self.len() >= SNAPSHOT_IMPORT_CHUNK_KEYS {
            self.flush(store)?;
        }
        Ok(())
    }

    fn flush(&mut self, store: &AtomicStorageV2) -> AtomicTokenResult<()> {
        if self.len() == 0 {
            return Ok(());
        }
        let assets = std::mem::take(&mut self.assets);
        let balances = std::mem::take(&mut self.balances);
        let nonces = std::mem::take(&mut self.nonces);
        let anchor_counts = std::mem::take(&mut self.anchor_counts);
        let processed_ops = std::mem::take(&mut self.processed_ops);
        store.apply_current_state_delta(assets, balances, nonces, anchor_counts, processed_ops)?;
        Ok(())
    }
}

struct RemoveDirOnDrop {
    path: PathBuf,
}

struct BootstrapProgressGuard<'a> {
    flag: &'a AtomicBool,
    previous: bool,
}

impl<'a> BootstrapProgressGuard<'a> {
    fn new(flag: &'a AtomicBool) -> Self {
        let previous = flag.swap(true, Ordering::SeqCst);
        Self { flag, previous }
    }
}

impl Drop for BootstrapProgressGuard<'_> {
    fn drop(&mut self) {
        self.flag.store(self.previous, Ordering::SeqCst);
    }
}

impl RemoveDirOnDrop {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl Drop for RemoveDirOnDrop {
    fn drop(&mut self) {
        match std::fs::remove_dir_all(&self.path) {
            Ok(()) => {}
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => warn!("[{IDENT}] failed removing Atomic temp directory `{}`: {err}", self.path.display()),
        }
    }
}

fn read_snapshot_record<T: serde::de::DeserializeOwned>(reader: &mut BufReader<File>, label: &str) -> AtomicTokenResult<T> {
    bincode::deserialize_from(reader)
        .map_err(|e| AtomicTokenError::Processing(format!("snapshot import failed: {label} decode failed: {e}")))
}

fn count_to_usize(count: u64, label: &str) -> AtomicTokenResult<usize> {
    usize::try_from(count)
        .map_err(|_| AtomicTokenError::Processing(format!("snapshot import failed: {label} count does not fit in usize")))
}

fn expected_processed_ops_for_replay_window(
    replay_window: &ReplayWindowTransferV2,
) -> AtomicTokenResult<(HashMap<BlockHash, ProcessedOp>, HashSet<BlockHash>)> {
    let mut expected_processed_ops = HashMap::new();
    let mut accepting_blocks_in_window = HashSet::new();
    for (accepting_block_hash, journal) in replay_window.journals_in_window.iter() {
        accepting_blocks_in_window.insert(*accepting_block_hash);
        if journal.added_processed_ops.len() != journal.tx_results.len() {
            return Err(AtomicTokenError::Processing(format!(
                "snapshot import failed: journal tx-result length mismatch for block `{accepting_block_hash}`"
            )));
        }
        for (txid, tx_result) in journal.added_processed_ops.iter().copied().zip(journal.tx_results.iter()) {
            if tx_result.txid != txid {
                return Err(AtomicTokenError::Processing(format!(
                    "snapshot import failed: journal txid mismatch for block `{accepting_block_hash}`"
                )));
            }
            let expected = ProcessedOp {
                accepting_block_hash: *accepting_block_hash,
                apply_status: tx_result.apply_status,
                noop_reason: tx_result.noop_reason,
            };
            if expected_processed_ops.insert(txid, expected).is_some() {
                return Err(AtomicTokenError::Processing(format!(
                    "snapshot import failed: duplicate processed txid `{txid}` in rollback window journals"
                )));
            }
        }
    }
    Ok((expected_processed_ops, accepting_blocks_in_window))
}

fn validate_snapshot_runtime_header(
    state: &AtomicTokenState,
    header: &SnapshotFileHeaderV2,
    replay_window: &ReplayWindowTransferV2,
) -> AtomicTokenResult<()> {
    if header.schema_version != crate::state::SNAPSHOT_SCHEMA_VERSION {
        return Err(AtomicTokenError::SnapshotSchemaMismatch {
            expected: crate::state::SNAPSHOT_SCHEMA_VERSION,
            actual: header.schema_version,
        });
    }
    if header.window_end_block_hash != header.at_block_hash {
        return Err(AtomicTokenError::Processing(
            "snapshot import failed: window_end_block_hash must equal at_block_hash".to_string(),
        ));
    }
    if state.applied_chain_order.last().copied() != Some(header.at_block_hash) {
        return Err(AtomicTokenError::Processing("snapshot import failed: applied_chain_order must end at at_block_hash".to_string()));
    }
    let expected_len = state.applied_chain_order.len();
    let unique_blocks: HashSet<BlockHash> = state.applied_chain_order.iter().copied().collect();
    if unique_blocks.len() != expected_len {
        return Err(AtomicTokenError::Processing(
            "snapshot import failed: applied_chain_order contains duplicate block hashes".to_string(),
        ));
    }
    if state.state_hash_by_block.len() != expected_len
        || state.applied_chain_order.iter().any(|hash| !state.state_hash_by_block.contains_key(hash))
    {
        return Err(AtomicTokenError::Processing(
            "snapshot import failed: state_hash_by_block must match applied_chain_order exactly".to_string(),
        ));
    }
    if state.event_sequence_by_block.len() != expected_len
        || state.applied_chain_order.iter().any(|hash| !state.event_sequence_by_block.contains_key(hash))
    {
        return Err(AtomicTokenError::Processing(
            "snapshot import failed: event_sequence_by_block must match applied_chain_order exactly".to_string(),
        ));
    }
    if state.state_hash_by_block.get(&header.at_block_hash).copied() != Some(header.state_hash_at_fp) {
        return Err(AtomicTokenError::Processing(
            "snapshot import failed: state_hash_by_block does not match state_hash_at_fp for at_block_hash".to_string(),
        ));
    }
    if state.events.iter().any(|event| event.sequence > header.next_event_sequence) {
        return Err(AtomicTokenError::Processing("snapshot import failed: event sequence exceeds next_event_sequence".to_string()));
    }
    let window_start_index =
        state.applied_chain_order.iter().position(|hash| *hash == header.window_start_block_hash).ok_or_else(|| {
            AtomicTokenError::Processing(format!(
                "snapshot import failed: window_start_block_hash `{}` not found in applied_chain_order",
                header.window_start_block_hash
            ))
        })?;
    let expected_window_len = state.applied_chain_order.len() - window_start_index;
    if replay_window.journals_in_window.len() != expected_window_len {
        return Err(AtomicTokenError::Processing(format!(
            "snapshot import failed: journals_in_window length mismatch ({} != {})",
            replay_window.journals_in_window.len(),
            expected_window_len
        )));
    }
    for (offset, (block_hash, _)) in replay_window.journals_in_window.iter().enumerate() {
        let expected_hash = state.applied_chain_order[window_start_index + offset];
        if *block_hash != expected_hash {
            return Err(AtomicTokenError::Processing(
                "snapshot import failed: journals_in_window order does not match canonical chain path".to_string(),
            ));
        }
    }
    Ok(())
}

fn import_snapshot_file_into_store(
    path: &Path,
    validated: &ValidatedSnapshotFileV2,
    store: Arc<AtomicStorageV2>,
) -> AtomicTokenResult<AtomicTokenState> {
    let snapshot_size = std::fs::metadata(path)
        .map_err(|e| AtomicTokenError::Processing(format!("snapshot import failed: metadata read failed: {e}")))?
        .len();
    let file = File::open(path)
        .map_err(|e| AtomicTokenError::Processing(format!("snapshot import failed: open `{}`: {e}", path.display())))?;
    let mut reader = BufReader::new(file);
    let decoded_header: SnapshotFileHeaderV2 = read_snapshot_record(&mut reader, "snapshot header")?;
    if decoded_header != validated.header {
        return Err(AtomicTokenError::Processing(
            "snapshot import failed: decoded snapshot header changed after manifest validation".to_string(),
        ));
    }
    let header = &validated.header;
    let counts = header.counts;

    let mut state = AtomicTokenState::new(header.protocol_version, header.network_id.clone());
    state.degraded = false;
    state.live_correct = false;
    state.next_event_sequence = header.next_event_sequence;

    for _ in 0..counts.state_hashes {
        let (block_hash, state_hash): (BlockHash, [u8; 32]) = read_snapshot_record(&mut reader, "state hash")?;
        if state.state_hash_by_block.insert(block_hash, state_hash).is_some() {
            return Err(AtomicTokenError::Processing(format!(
                "snapshot import failed: duplicate state hash checkpoint for block `{block_hash}`"
            )));
        }
    }
    for _ in 0..counts.event_sequences {
        let (block_hash, sequence): (BlockHash, u64) = read_snapshot_record(&mut reader, "event sequence")?;
        if state.event_sequence_by_block.insert(block_hash, sequence).is_some() {
            return Err(AtomicTokenError::Processing(format!(
                "snapshot import failed: duplicate event sequence checkpoint for block `{block_hash}`"
            )));
        }
    }

    let mut chain_order_entries = Vec::with_capacity(count_to_usize(counts.chain_order, "chain order")?);
    for _ in 0..counts.chain_order {
        let (index, block_hash): (u64, BlockHash) = read_snapshot_record(&mut reader, "chain order")?;
        chain_order_entries.push((index, block_hash));
    }
    chain_order_entries.sort_by_key(|(index, _)| *index);
    for (expected_index, (index, block_hash)) in chain_order_entries.into_iter().enumerate() {
        if index != expected_index as u64 {
            return Err(AtomicTokenError::Processing(
                "snapshot import failed: chain_order indexes must be contiguous from zero".to_string(),
            ));
        }
        state.applied_chain_order.push(block_hash);
    }

    state.events.reserve(count_to_usize(counts.events, "events")?);
    for _ in 0..counts.events {
        let event: TokenEvent = read_snapshot_record(&mut reader, "event")?;
        state.events.push(event);
    }
    state.block_journals = validated.replay_window.journals_in_window.iter().cloned().collect();
    state.rebuild_event_id_index();
    validate_snapshot_runtime_header(&state, header, &validated.replay_window)?;

    store.persist_state(&state)?;
    state.attach_state_store(store.clone());
    state.clear_persistent_state_overlay();

    let (expected_processed_ops, accepting_blocks_in_window) = expected_processed_ops_for_replay_window(&validated.replay_window)?;
    let mut seen_window_processed_ops = HashSet::new();
    let mut chunk = SnapshotStateImportChunk::default();
    for _ in 0..counts.assets {
        let (asset_id, asset): ([u8; 32], TokenAsset) = read_snapshot_record(&mut reader, "asset")?;
        if asset.asset_id != asset_id {
            return Err(AtomicTokenError::Processing("snapshot import failed: asset key/id mismatch".to_string()));
        }
        chunk.assets.push((asset_id, Some(asset)));
        chunk.flush_if_full(&store)?;
    }
    for _ in 0..counts.balances {
        let (key, amount): (BalanceKey, u128) = read_snapshot_record(&mut reader, "balance")?;
        chunk.balances.push((key, (amount > 0).then_some(amount)));
        chunk.flush_if_full(&store)?;
    }
    for _ in 0..counts.nonces {
        let (key, nonce): (NonceKey, u64) = read_snapshot_record(&mut reader, "nonce")?;
        chunk.nonces.push((key, (nonce != 1).then_some(nonce)));
        chunk.flush_if_full(&store)?;
    }
    for _ in 0..counts.anchor_counts {
        let (owner_id, count): ([u8; 32], u64) = read_snapshot_record(&mut reader, "anchor count")?;
        chunk.anchor_counts.push((owner_id, (count > 0).then_some(count)));
        chunk.flush_if_full(&store)?;
    }
    for _ in 0..counts.processed_ops {
        let (txid, op): (BlockHash, ProcessedOp) = read_snapshot_record(&mut reader, "processed op")?;
        if accepting_blocks_in_window.contains(&op.accepting_block_hash) {
            match expected_processed_ops.get(&txid) {
                Some(expected) if *expected == op => {
                    seen_window_processed_ops.insert(txid);
                }
                Some(_) => {
                    return Err(AtomicTokenError::Processing(format!(
                        "snapshot import failed: processed txid `{txid}` does not match rollback window journal"
                    )));
                }
                None => {
                    return Err(AtomicTokenError::Processing(
                        "snapshot import failed: processed_ops contains entries outside the rollback window".to_string(),
                    ));
                }
            }
        }
        chunk.processed_ops.push((txid, Some(op)));
        chunk.flush_if_full(&store)?;
    }
    chunk.flush(&store)?;
    for txid in expected_processed_ops.keys() {
        if !seen_window_processed_ops.contains(txid) {
            return Err(AtomicTokenError::Processing(format!(
                "snapshot import failed: processed txid `{txid}` is missing from snapshot processed_ops"
            )));
        }
    }

    let decoded_pos = reader
        .stream_position()
        .map_err(|e| AtomicTokenError::Processing(format!("snapshot import failed: decode position check failed: {e}")))?;
    if decoded_pos != snapshot_size {
        return Err(AtomicTokenError::Processing("snapshot import failed: trailing bytes after snapshot payload".to_string()));
    }
    let imported_root = store
        .current_root()?
        .ok_or_else(|| AtomicTokenError::Processing("snapshot import failed: imported V2 store has no current root".to_string()))?;
    if imported_root != header.state_hash_at_fp {
        return Err(AtomicTokenError::Processing("snapshot import failed: state hash mismatch at snapshot at_block_hash".to_string()));
    }
    Ok(state)
}

fn copy_snapshot_store_into_active(
    source: &AtomicStorageV2,
    target: Arc<AtomicStorageV2>,
    mut state: AtomicTokenState,
) -> AtomicTokenResult<AtomicTokenState> {
    let expected_root = source
        .current_root()?
        .ok_or_else(|| AtomicTokenError::Processing("snapshot import failed: staged V2 store has no current root".to_string()))?;
    state.clear_persistent_state_overlay();
    target.persist_state(&state)?;
    let copied_root = target.replace_current_state_from(source, &state)?;
    if copied_root != expected_root {
        return Err(AtomicTokenError::Processing(
            "snapshot import failed: active V2 store root mismatch after snapshot swap".to_string(),
        ));
    }
    state.clear_persistent_state_overlay();
    state.attach_state_store(target);
    Ok(state)
}

#[cfg(test)]
fn build_snapshot_manifest(
    path: &Path,
    snapshot_bytes: &[u8],
    replay_window_bytes: &[u8],
    header: &SnapshotFileHeaderV2,
) -> AtomicTokenResult<SnapshotManifestV2> {
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
    Ok(SnapshotManifestV2 {
        schema_version: header.schema_version,
        protocol_version: header.protocol_version,
        network_id: header.network_id.clone(),
        snapshot_file_name,
        snapshot_file_size,
        snapshot_file_hash: hash_snapshot_bytes(snapshot_bytes),
        snapshot_chunk_size,
        snapshot_chunk_hashes: chunk_hashes(snapshot_bytes, snapshot_chunk_size as usize),
        replay_window_size,
        replay_window_hash: hash_snapshot_bytes(replay_window_bytes),
        replay_window_chunk_size,
        replay_window_chunk_hashes: chunk_hashes(replay_window_bytes, replay_window_chunk_size as usize),
        at_block_hash: hash_to_array(header.at_block_hash),
        at_daa_score: header.at_daa_score,
        state_hash_at_fp: header.state_hash_at_fp,
        state_hash_at_window_start_parent: header.state_hash_at_window_start_parent,
        window_start_block_hash: hash_to_array(header.window_start_block_hash),
        window_start_parent_block_hash: hash_to_array(header.window_start_parent_block_hash),
        window_end_block_hash: hash_to_array(header.window_end_block_hash),
    })
}

fn validate_snapshot_manifest_and_decode(
    path: &Path,
    expected_protocol_version: u16,
    expected_network_id: &str,
) -> AtomicTokenResult<ValidatedSnapshotFileV2> {
    let manifest_bytes = std::fs::read(snapshot_manifest_path(path))
        .map_err(|e| AtomicTokenError::Processing(format!("snapshot manifest read failed: {e}")))?;
    let manifest = SnapshotManifestV2::try_from_slice(&manifest_bytes)
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
    let (snapshot_file_size, snapshot_file_hash, snapshot_chunk_hashes) =
        hash_file_and_chunks(path, manifest.snapshot_chunk_size as usize, "snapshot import")?;
    if manifest.snapshot_file_size != snapshot_file_size {
        return Err(AtomicTokenError::Processing("snapshot import failed: manifest snapshot size mismatch".to_string()));
    }
    if manifest.snapshot_file_hash != snapshot_file_hash {
        return Err(AtomicTokenError::Processing("snapshot import failed: manifest snapshot hash mismatch".to_string()));
    }
    if snapshot_chunk_hashes != manifest.snapshot_chunk_hashes {
        return Err(AtomicTokenError::Processing("snapshot import failed: manifest snapshot chunk hashes mismatch".to_string()));
    }

    let mut snapshot_file =
        File::open(path).map_err(|e| AtomicTokenError::Processing(format!("snapshot read failed: open `{}`: {e}", path.display())))?;
    let header: SnapshotFileHeaderV2 = bincode::deserialize_from(&mut snapshot_file)
        .map_err(|e| AtomicTokenError::Processing(format!("snapshot header decode failed: {e}")))?;
    if header.schema_version != manifest.schema_version
        || header.protocol_version != manifest.protocol_version
        || header.network_id != manifest.network_id
        || hash_to_array(header.at_block_hash) != manifest.at_block_hash
        || header.at_daa_score != manifest.at_daa_score
        || header.state_hash_at_fp != manifest.state_hash_at_fp
        || header.state_hash_at_window_start_parent != manifest.state_hash_at_window_start_parent
        || hash_to_array(header.window_start_block_hash) != manifest.window_start_block_hash
        || hash_to_array(header.window_start_parent_block_hash) != manifest.window_start_parent_block_hash
        || hash_to_array(header.window_end_block_hash) != manifest.window_end_block_hash
    {
        return Err(AtomicTokenError::Processing(
            "snapshot import failed: manifest metadata does not match decoded snapshot header".to_string(),
        ));
    }
    let replay_path = snapshot_replay_path(path);
    let (replay_window_size, replay_window_hash, replay_window_chunk_hashes) =
        hash_file_and_chunks(&replay_path, manifest.replay_window_chunk_size as usize, "snapshot replay import")?;
    if manifest.replay_window_size != replay_window_size {
        return Err(AtomicTokenError::Processing("snapshot import failed: manifest replay window size mismatch".to_string()));
    }
    if manifest.replay_window_hash != replay_window_hash {
        return Err(AtomicTokenError::Processing("snapshot import failed: manifest replay window hash mismatch".to_string()));
    }
    if replay_window_chunk_hashes != manifest.replay_window_chunk_hashes {
        return Err(AtomicTokenError::Processing("snapshot import failed: manifest replay window chunk hashes mismatch".to_string()));
    }
    let mut replay_file = File::open(&replay_path)
        .map_err(|e| AtomicTokenError::Processing(format!("snapshot replay read failed: open `{}`: {e}", replay_path.display())))?;
    let replay_window: ReplayWindowTransferV2 = bincode::deserialize_from(&mut replay_file)
        .map_err(|e| AtomicTokenError::Processing(format!("snapshot replay decode failed: {e}")))?;
    let replay_decoded_pos = replay_file
        .seek(SeekFrom::Current(0))
        .map_err(|e| AtomicTokenError::Processing(format!("snapshot replay decode position check failed: {e}")))?;
    if replay_decoded_pos != manifest.replay_window_size {
        return Err(AtomicTokenError::Processing("snapshot import failed: trailing bytes after replay window payload".to_string()));
    }
    if replay_window.protocol_version != header.protocol_version
        || replay_window.network_id != header.network_id
        || replay_window.window_start_block_hash != hash_to_array(header.window_start_block_hash)
        || replay_window.window_end_block_hash != hash_to_array(header.window_end_block_hash)
    {
        return Err(AtomicTokenError::Processing(
            "snapshot import failed: replay window metadata does not match decoded snapshot contents".to_string(),
        ));
    }
    expected_processed_ops_for_replay_window(&replay_window)?;
    Ok(ValidatedSnapshotFileV2 { header, replay_window })
}

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
        let manifest = SnapshotManifestV2::try_from_slice(&manifest_bytes)
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

fn cached_snapshot_parent_checkpoint_matches_current_state(entry: &SnapshotCatalogEntry, state: &AtomicTokenState) -> bool {
    let expected_parent_hash =
        state.state_hash_by_block.get(&BlockHash::from_bytes(entry.manifest.window_start_parent_block_hash)).copied().or_else(|| {
            state
                .materialize_context_at_block(
                    BlockHash::from_bytes(entry.manifest.window_start_parent_block_hash),
                    state.runtime_state(false),
                )
                .map(|context| context.state_hash)
        });
    if entry.manifest.state_hash_at_window_start_parent != expected_parent_hash {
        trace!(
            "[{IDENT}] ignoring cached Atomic bootstrap snapshot `{}`: stale window_start parent checkpoint",
            entry.snapshot_path.display()
        );
        return false;
    }

    true
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

fn short_hex_for_log(data: &[u8]) -> String {
    if data.is_empty() {
        return "<empty>".to_string();
    }
    if data.len() <= 8 {
        return hex_encode(data);
    }
    format!("{}...{}", hex_encode(&data[..4]), hex_encode(&data[data.len() - 4..]))
}

fn unique_atomic_temp_dir(atomic_data_dir: &Path, label: &str) -> AtomicTokenResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|duration| duration.as_nanos()).unwrap_or(0);
    let temp_root = atomic_data_dir.join("tmp");
    std::fs::create_dir_all(&temp_root).map_err(|err| {
        AtomicTokenError::Processing(format!("failed creating Atomic temp directory `{}`: {err}", temp_root.display()))
    })?;
    prune_stale_atomic_temp_dirs(&temp_root);
    Ok(temp_root.join(format!("cryptix-atomic-{label}-{}-{nanos}", std::process::id())))
}

fn prune_stale_atomic_temp_dirs(temp_root: &Path) {
    let Ok(entries) = std::fs::read_dir(temp_root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.starts_with("cryptix-atomic-") {
            continue;
        }
        let stale = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .ok()
            .and_then(|modified| SystemTime::now().duration_since(modified).ok())
            .is_some_and(|age| age >= ATOMIC_TEMP_DIR_MAX_AGE);
        if stale {
            match std::fs::remove_dir_all(&path) {
                Ok(()) => info!("[{IDENT}] removed stale Atomic temp directory `{}`", path.display()),
                Err(err) if err.kind() == ErrorKind::NotFound => {}
                Err(err) => trace!("[{IDENT}] failed removing stale Atomic temp directory `{}`: {err}", path.display()),
            }
        }
    }
}

fn format_bytes_for_log(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    let bytes_f = bytes as f64;
    if bytes_f >= GIB {
        format!("{:.2} GiB", bytes_f / GIB)
    } else if bytes_f >= MIB {
        format!("{:.2} MiB", bytes_f / MIB)
    } else if bytes_f >= KIB {
        format!("{:.2} KiB", bytes_f / KIB)
    } else {
        format!("{bytes} B")
    }
}

fn log_state_footprint(label: &str, footprint: AtomicTokenStateFootprint, state_store_bytes: Option<u64>) {
    info!(
        "[{IDENT}] Cryptix Atomic state footprint ({label}): retained_blocks={}, events={}, journals={}, checkpoints={}, event_checkpoints={}, state_store={}",
        footprint.retained_blocks,
        footprint.events,
        footprint.block_journals,
        footprint.state_hash_checkpoints,
        footprint.event_sequence_checkpoints,
        state_store_bytes.map(format_bytes_for_log).unwrap_or_else(|| "n/a".to_string())
    );
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
    use crate::state::{BlockJournal, SNAPSHOT_SCHEMA_VERSION};
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

    struct MinimalSnapshotFixture {
        header: SnapshotFileHeaderV2,
        replay_window: ReplayWindowTransferV2,
    }

    fn minimal_snapshot(protocol_version: u16, network_id: &str) -> MinimalSnapshotFixture {
        minimal_snapshot_at(protocol_version, network_id, BlockHash::from_u64_word(1), 123)
    }

    fn minimal_snapshot_at(
        protocol_version: u16,
        network_id: &str,
        at_block_hash: BlockHash,
        at_daa_score: u64,
    ) -> MinimalSnapshotFixture {
        let window_start_parent_block_hash = BlockHash::from_u64_word(0);
        let mut state = AtomicTokenState::new(protocol_version, network_id.to_string());
        let state_hash = state.compute_state_hash();
        state.state_hash_by_block.insert(at_block_hash, state_hash);
        state.event_sequence_by_block.insert(at_block_hash, 0);
        state.applied_chain_order.push(at_block_hash);

        let header = SnapshotFileHeaderV2 {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            protocol_version,
            network_id: network_id.to_string(),
            at_block_hash,
            at_daa_score,
            state_hash_at_fp: state_hash,
            state_hash_at_window_start_parent: None,
            window_start_block_hash: at_block_hash,
            window_start_parent_block_hash,
            window_end_block_hash: at_block_hash,
            next_event_sequence: 0,
            counts: AtomicStorageSnapshotCounts { state_hashes: 1, event_sequences: 1, chain_order: 1, ..Default::default() },
        };
        let replay_window = ReplayWindowTransferV2 {
            protocol_version,
            network_id: network_id.to_string(),
            window_start_block_hash: hash_to_array(at_block_hash),
            window_end_block_hash: hash_to_array(at_block_hash),
            journals_in_window: vec![(at_block_hash, BlockJournal::default())],
        };
        MinimalSnapshotFixture { header, replay_window }
    }

    fn encode_snapshot_file(fixture: &MinimalSnapshotFixture) -> Vec<u8> {
        let mut bytes = Vec::new();
        let header = &fixture.header;
        bincode::serialize_into(&mut bytes, header).expect("encode snapshot header");
        bincode::serialize_into(&mut bytes, &(header.at_block_hash, header.state_hash_at_fp)).expect("encode state hash");
        bincode::serialize_into(&mut bytes, &(header.at_block_hash, 0u64)).expect("encode event sequence");
        bincode::serialize_into(&mut bytes, &(0u64, header.at_block_hash)).expect("encode chain order");
        bytes
    }

    fn encode_replay_window_transfer(replay_window: &ReplayWindowTransferV2) -> Vec<u8> {
        bincode::serialize(replay_window).expect("encode replay")
    }

    #[test]
    fn list_snapshot_catalog_requires_replay_sidecar() {
        let dir = unique_temp_dir("snapshot-catalog");
        let snapshot_path = dir.join("atomic-snapshot-1.bin");
        let snapshot = minimal_snapshot(TOKEN_PROTOCOL_VERSION, "cryptix-simnet");
        let snapshot_bytes = encode_snapshot_file(&snapshot);
        let replay_window_bytes = encode_replay_window_transfer(&snapshot.replay_window);
        let manifest =
            build_snapshot_manifest(&snapshot_path, &snapshot_bytes, &replay_window_bytes, &snapshot.header).expect("manifest");
        let manifest_bytes = borsh::to_vec(&manifest).expect("encode manifest");

        fs::write(&snapshot_path, snapshot_bytes).expect("write snapshot");
        fs::write(snapshot_manifest_path(&snapshot_path), manifest_bytes).expect("write manifest");
        // Intentionally do not write the replay sidecar.

        let catalog = list_snapshot_catalog(&dir).expect("list catalog");
        assert!(catalog.is_empty());

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn validate_snapshot_manifest_accepts_matching_replay_sidecar() {
        let dir = unique_temp_dir("snapshot-manifest-replay");
        let snapshot_path = dir.join("atomic-snapshot-1.bin");
        let snapshot = minimal_snapshot(TOKEN_PROTOCOL_VERSION, "cryptix-simnet");
        let snapshot_bytes = encode_snapshot_file(&snapshot);
        let replay_window_bytes = encode_replay_window_transfer(&snapshot.replay_window);
        let manifest =
            build_snapshot_manifest(&snapshot_path, &snapshot_bytes, &replay_window_bytes, &snapshot.header).expect("manifest");
        let manifest_bytes = borsh::to_vec(&manifest).expect("encode manifest");

        fs::write(&snapshot_path, &snapshot_bytes).expect("write snapshot");
        fs::write(snapshot_replay_path(&snapshot_path), replay_window_bytes).expect("write replay");
        fs::write(snapshot_manifest_path(&snapshot_path), manifest_bytes).expect("write manifest");

        validate_snapshot_manifest_and_decode(&snapshot_path, TOKEN_PROTOCOL_VERSION, "cryptix-simnet")
            .expect("manifest should validate against sidecar");

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn validate_snapshot_manifest_rejects_replay_sidecar_not_matching_snapshot_journals() {
        let dir = unique_temp_dir("snapshot-manifest-replay-mismatch");
        let snapshot_path = dir.join("atomic-snapshot-1.bin");
        let snapshot = minimal_snapshot(TOKEN_PROTOCOL_VERSION, "cryptix-simnet");
        let snapshot_bytes = encode_snapshot_file(&snapshot);
        let mut replay_window = snapshot.replay_window.clone();
        replay_window.journals_in_window[0].1.added_processed_ops.push(BlockHash::from_u64_word(42));
        let replay_window_bytes = encode_replay_window_transfer(&replay_window);
        let manifest =
            build_snapshot_manifest(&snapshot_path, &snapshot_bytes, &replay_window_bytes, &snapshot.header).expect("manifest");
        let manifest_bytes = borsh::to_vec(&manifest).expect("encode manifest");

        fs::write(&snapshot_path, &snapshot_bytes).expect("write snapshot");
        fs::write(snapshot_replay_path(&snapshot_path), replay_window_bytes).expect("write replay");
        fs::write(snapshot_manifest_path(&snapshot_path), manifest_bytes).expect("write manifest");

        let err = validate_snapshot_manifest_and_decode(&snapshot_path, TOKEN_PROTOCOL_VERSION, "cryptix-simnet")
            .expect_err("manifest sidecar semantics must be checked");
        assert!(err.to_string().contains("journal tx-result length mismatch"));

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
            let snapshot =
                minimal_snapshot_at(TOKEN_PROTOCOL_VERSION, "cryptix-simnet", BlockHash::from_u64_word(10_000 + i), 100 + i);

            let snapshot_bytes = encode_snapshot_file(&snapshot);
            let replay_window_bytes = encode_replay_window_transfer(&snapshot.replay_window);
            let manifest =
                build_snapshot_manifest(&snapshot_path, &snapshot_bytes, &replay_window_bytes, &snapshot.header).expect("manifest");
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
