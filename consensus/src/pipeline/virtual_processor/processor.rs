use crate::{
    consensus::{
        services::{
            ConsensusServices, DbBlockDepthManager, DbDagTraversalManager, DbGhostdagManager, DbParentsManager, DbPruningPointManager,
            DbWindowManager,
        },
        storage::ConsensusStorage,
    },
    constants::BLOCK_VERSION,
    errors::RuleError,
    model::{
        services::{
            reachability::{MTReachabilityService, ReachabilityService},
            relations::MTRelationsService,
        },
        stores::{
            acceptance_data::{AcceptanceDataStoreReader, DbAcceptanceDataStore},
            atomic_state::{AtomicConsensusRootAccumulator, AtomicConsensusState, AtomicNonceKey, DbAtomicStateStore},
            block_transactions::{BlockTransactionsStoreReader, DbBlockTransactionsStore},
            daa::DbDaaStore,
            depth::{DbDepthStore, DepthStoreReader},
            ghostdag::{DbGhostdagStore, GhostdagData, GhostdagStoreReader},
            headers::{DbHeadersStore, HeaderStoreReader},
            past_pruning_points::DbPastPruningPointsStore,
            pruning::{DbPruningStore, PruningStoreReader},
            pruning_utxoset::PruningUtxosetStores,
            reachability::DbReachabilityStore,
            relations::{DbRelationsStore, RelationsStoreReader},
            selected_chain::{DbSelectedChainStore, SelectedChainStore, SelectedChainStoreReader},
            statuses::{DbStatusesStore, StatusesStoreBatchExtensions, StatusesStoreReader},
            tips::{DbTipsStore, TipsStore, TipsStoreReader},
            utxo_diffs::{DbUtxoDiffsStore, UtxoDiffsStoreReader},
            utxo_multisets::{DbUtxoMultisetsStore, UtxoMultisetsStoreReader},
            virtual_state::{LkgVirtualState, VirtualState, VirtualStateStoreReader, VirtualStores},
            DB,
        },
    },
    params::Params,
    pipeline::{
        deps_manager::VirtualStateProcessingMessage,
        pruning_processor::processor::PruningProcessingMessage,
        virtual_processor::utxo_validation::{
            atomic_nonce_key_for_op, AtomicBlockStateGrowth, AtomicCreationContext, UtxoProcessingContext,
        },
        ProcessingCounters,
    },
    processes::{
        coinbase::CoinbaseManager,
        ghostdag::ordering::SortableBlock,
        transaction_validator::{
            errors::{TxResult, TxRuleError},
            transaction_validator_populated::{atomic_owner_id_from_script, parse_atomic_payload, AtomicPayloadOp, TxValidationFlags},
            TransactionValidator,
        },
        window::WindowManager,
    },
};
use cryptix_consensus_core::{
    acceptance_data::AcceptanceData,
    api::args::{TransactionValidationArgs, TransactionValidationBatchArgs},
    block::{BlockTemplate, MutableBlock, TemplateBuildMode, TemplateTransactionSelector},
    blockstatus::BlockStatus::{StatusDisqualifiedFromChain, StatusHeaderOnly, StatusInvalid, StatusUTXOValid},
    coinbase::MinerData,
    config::genesis::GenesisBlock,
    errors::consensus::{ConsensusError, ConsensusResult},
    header::Header,
    merkle::calc_hash_merkle_root,
    pruning::{PruningPointAtomicState, PruningPointsList},
    tx::{MutableTransaction, PopulatedTransaction, Transaction, TransactionOutpoint, UtxoEntry, VerifiableTransaction},
    utxo::{
        utxo_diff::{ImmutableUtxoDiff, UtxoDiff},
        utxo_view::{UtxoView, UtxoViewComposition},
    },
    BlockHashSet, ChainPath,
};
use cryptix_consensus_notify::{
    notification::{
        NewBlockTemplateNotification, Notification, SinkBlueScoreChangedNotification, UtxosChangedNotification,
        VirtualChainChangedNotification, VirtualDaaScoreChangedNotification,
    },
    root::ConsensusNotificationRoot,
};
use cryptix_consensusmanager::SessionLock;
use cryptix_core::{debug, info, time::unix_now, trace, warn};
use cryptix_database::prelude::{StoreError, StoreResultEmptyTuple, StoreResultExtensions};
use cryptix_hashes::Hash;
use cryptix_muhash::MuHash;
use cryptix_notify::{events::EventType, notifier::Notify};

use super::errors::{PruningImportError, PruningImportResult};
use crossbeam_channel::{Receiver as CrossbeamReceiver, RecvTimeoutError, Sender as CrossbeamSender};
use cryptix_consensus_core::tx::ValidatedTransaction;
use cryptix_utils::binary_heap::BinaryHeapExtensions;
use itertools::Itertools;
use parking_lot::{Mutex, RwLock, RwLockUpgradableReadGuard};
use rand::{seq::SliceRandom, Rng};
use rayon::{
    prelude::{IntoParallelRefMutIterator, ParallelIterator},
    ThreadPool,
};
use rocksdb::WriteBatch;
use std::{
    cmp::min,
    collections::{BinaryHeap, HashMap, HashSet, VecDeque},
    ops::Deref,
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
};

const ATOMIC_CONSENSUS_LOG_INTERVAL: Duration = Duration::from_secs(60);
const ATOMIC_CONSENSUS_VAULT_LOG_COUNT_LIMIT: usize = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct AtomicTxOrderPriority {
    nonce_key: AtomicNonceKey,
    nonce: u64,
    pool_asset_id: [u8; 32],
    pool_nonce: u64,
    txid_bytes: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
struct AtomicTxOrderInfo {
    priority: AtomicTxOrderPriority,
    nonce_key: AtomicNonceKey,
    nonce: u64,
    pool: Option<([u8; 32], u64)>,
    creates_asset_id: Option<[u8; 32]>,
    references_asset_id: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct AtomicConsensusLogSummary {
    root: [u8; 32],
    root_only: bool,
    assets: u64,
    balances: u64,
    nonces: u64,
    anchors: u64,
    vaults: Option<usize>,
}

#[derive(Debug, Default)]
struct AtomicConsensusLogState {
    last_log_at: Option<Instant>,
}

pub struct VirtualStateProcessor {
    // Channels
    receiver: CrossbeamReceiver<VirtualStateProcessingMessage>,
    pruning_sender: CrossbeamSender<PruningProcessingMessage>,
    pruning_receiver: CrossbeamReceiver<PruningProcessingMessage>,

    // Thread pool
    pub(super) thread_pool: Arc<ThreadPool>,

    // DB
    db: Arc<DB>,

    // Config
    pub(super) genesis: GenesisBlock,
    pub(super) max_block_parents: u8,
    pub(super) mergeset_size_limit: u64,
    pub(super) pruning_depth: u64,

    // Stores
    pub(super) statuses_store: Arc<RwLock<DbStatusesStore>>,
    pub(super) ghostdag_primary_store: Arc<DbGhostdagStore>,
    pub(super) headers_store: Arc<DbHeadersStore>,
    pub(super) daa_excluded_store: Arc<DbDaaStore>,
    pub(super) block_transactions_store: Arc<DbBlockTransactionsStore>,
    pub(super) pruning_point_store: Arc<RwLock<DbPruningStore>>,
    pub(super) past_pruning_points_store: Arc<DbPastPruningPointsStore>,
    pub(super) body_tips_store: Arc<RwLock<DbTipsStore>>,
    pub(super) depth_store: Arc<DbDepthStore>,
    pub(super) selected_chain_store: Arc<RwLock<DbSelectedChainStore>>,

    // Utxo-related stores
    pub(super) utxo_diffs_store: Arc<DbUtxoDiffsStore>,
    pub(super) utxo_multisets_store: Arc<DbUtxoMultisetsStore>,
    pub(super) acceptance_data_store: Arc<DbAcceptanceDataStore>,
    pub(super) atomic_state_store: Arc<DbAtomicStateStore>,
    pub(super) virtual_stores: Arc<RwLock<VirtualStores>>,
    pub(super) pruning_utxoset_stores: Arc<RwLock<PruningUtxosetStores>>,

    /// The "last known good" virtual state. To be used by any logic which does not want to wait
    /// for a possible virtual state write to complete but can rather settle with the last known state
    pub lkg_virtual_state: LkgVirtualState,

    // Managers and services
    pub(super) ghostdag_manager: DbGhostdagManager,
    pub(super) reachability_service: MTReachabilityService<DbReachabilityStore>,
    pub(super) relations_service: MTRelationsService<DbRelationsStore>,
    pub(super) dag_traversal_manager: DbDagTraversalManager,
    pub(super) window_manager: DbWindowManager,
    pub(super) coinbase_manager: CoinbaseManager,
    pub(super) transaction_validator: TransactionValidator,
    pub(super) pruning_point_manager: DbPruningPointManager,
    pub(super) parents_manager: DbParentsManager,
    pub(super) depth_manager: DbBlockDepthManager,

    // Pruning lock
    pruning_lock: SessionLock,

    // Notifier
    notification_root: Arc<ConsensusNotificationRoot>,

    // Counters
    counters: Arc<ProcessingCounters>,
    atomic_consensus_log_state: Mutex<AtomicConsensusLogState>,

    // Storage mass hardfork DAA score
    pub(crate) storage_mass_activation_daa_score: u64,

    pub(super) atomic_max_new_assets_per_block: usize,
    pub(super) atomic_max_new_balance_keys_per_block: usize,
    pub(super) atomic_max_new_nonce_keys_per_block: usize,
    pub(super) atomic_max_new_pools_per_block: usize,
    pub(super) atomic_max_new_anchor_owner_keys_per_block: usize,
}

impl VirtualStateProcessor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        receiver: CrossbeamReceiver<VirtualStateProcessingMessage>,
        pruning_sender: CrossbeamSender<PruningProcessingMessage>,
        pruning_receiver: CrossbeamReceiver<PruningProcessingMessage>,
        thread_pool: Arc<ThreadPool>,
        params: &Params,
        db: Arc<DB>,
        storage: &Arc<ConsensusStorage>,
        services: &Arc<ConsensusServices>,
        pruning_lock: SessionLock,
        notification_root: Arc<ConsensusNotificationRoot>,
        counters: Arc<ProcessingCounters>,
    ) -> Self {
        Self {
            receiver,
            pruning_sender,
            pruning_receiver,
            thread_pool,

            genesis: params.genesis.clone(),
            max_block_parents: params.max_block_parents,
            mergeset_size_limit: params.mergeset_size_limit,
            pruning_depth: params.pruning_depth,

            db,
            statuses_store: storage.statuses_store.clone(),
            headers_store: storage.headers_store.clone(),
            ghostdag_primary_store: storage.ghostdag_primary_store.clone(),
            daa_excluded_store: storage.daa_excluded_store.clone(),
            block_transactions_store: storage.block_transactions_store.clone(),
            pruning_point_store: storage.pruning_point_store.clone(),
            past_pruning_points_store: storage.past_pruning_points_store.clone(),
            body_tips_store: storage.body_tips_store.clone(),
            depth_store: storage.depth_store.clone(),
            selected_chain_store: storage.selected_chain_store.clone(),
            utxo_diffs_store: storage.utxo_diffs_store.clone(),
            utxo_multisets_store: storage.utxo_multisets_store.clone(),
            acceptance_data_store: storage.acceptance_data_store.clone(),
            atomic_state_store: storage.atomic_state_store.clone(),
            virtual_stores: storage.virtual_stores.clone(),
            pruning_utxoset_stores: storage.pruning_utxoset_stores.clone(),
            lkg_virtual_state: storage.lkg_virtual_state.clone(),

            ghostdag_manager: services.ghostdag_primary_manager.clone(),
            reachability_service: services.reachability_service.clone(),
            relations_service: services.relations_service.clone(),
            dag_traversal_manager: services.dag_traversal_manager.clone(),
            window_manager: services.window_manager.clone(),
            coinbase_manager: services.coinbase_manager.clone(),
            transaction_validator: services.transaction_validator.clone(),
            pruning_point_manager: services.pruning_point_manager.clone(),
            parents_manager: services.parents_manager.clone(),
            depth_manager: services.depth_manager.clone(),

            pruning_lock,
            notification_root,
            counters,
            atomic_consensus_log_state: Mutex::new(AtomicConsensusLogState::default()),
            storage_mass_activation_daa_score: params.storage_mass_activation_daa_score,
            atomic_max_new_assets_per_block: params.atomic_max_new_assets_per_block,
            atomic_max_new_balance_keys_per_block: params.atomic_max_new_balance_keys_per_block,
            atomic_max_new_nonce_keys_per_block: params.atomic_max_new_nonce_keys_per_block,
            atomic_max_new_pools_per_block: params.atomic_max_new_pools_per_block,
            atomic_max_new_anchor_owner_keys_per_block: params.atomic_max_new_anchor_owner_keys_per_block,
        }
    }

    pub fn worker(self: &Arc<Self>) {
        'outer: loop {
            let msg = match self.receiver.recv_timeout(ATOMIC_CONSENSUS_LOG_INTERVAL) {
                Ok(msg) => msg,
                Err(RecvTimeoutError::Timeout) => {
                    self.log_current_atomic_consensus_state("periodic");
                    continue;
                }
                Err(RecvTimeoutError::Disconnected) => break,
            };
            if msg.is_exit_message() {
                break;
            }

            // Once a task arrived, collect all pending tasks from the channel.
            // This is done since virtual processing is not a per-block
            // operation, so it benefits from max available info

            let messages: Vec<VirtualStateProcessingMessage> = std::iter::once(msg).chain(self.receiver.try_iter()).collect();
            trace!("virtual processor received {} tasks", messages.len());

            self.resolve_virtual();

            let statuses_read = self.statuses_store.read();
            for msg in messages {
                match msg {
                    VirtualStateProcessingMessage::Exit => break 'outer,
                    VirtualStateProcessingMessage::Process(task, virtual_state_result_transmitter) => {
                        // We don't care if receivers were dropped
                        let _ = virtual_state_result_transmitter.send(Ok(statuses_read.get(task.block().hash()).unwrap()));
                    }
                };
            }
        }

        // Pass the exit signal on to the following processor
        self.pruning_sender.send(PruningProcessingMessage::Exit).unwrap();
    }

    pub(crate) fn resolve_virtual(self: &Arc<Self>) {
        self.repair_anchor_only_virtual_atomic_state_if_possible();
        self.repair_virtual_state_from_selected_chain_if_inconsistent("virtual resolve");
        let pruning_point = self.pruning_point_store.read().pruning_point().unwrap();
        let virtual_read = self.virtual_stores.upgradable_read();
        let prev_state = virtual_read.state.get().unwrap();
        let finality_point = self.virtual_finality_point(&prev_state.ghostdag_data, pruning_point);
        self.sanitize_disqualified_body_tips(prev_state.ghostdag_data.selected_parent);

        // PRUNE SAFETY: in order to avoid locking the prune lock throughout virtual resolving we make sure
        // to only process blocks in the future of the finality point (F) which are never pruned (since finality depth << pruning depth).
        // This is justified since:
        //      1. Tips which are not in the future of F definitely don't have F on their chain
        //         hence cannot become the next sink (due to finality violation).
        //      2. Such tips cannot be merged by virtual since they are violating the merge depth
        //         bound (merge depth <= finality depth).
        // (both claims are true by induction for any block in their past as well)
        let prune_guard = self.pruning_lock.blocking_read();
        let tips = self
            .body_tips_store
            .read()
            .get()
            .unwrap()
            .read()
            .iter()
            .copied()
            .filter(|&h| self.reachability_service.is_dag_ancestor_of(finality_point, h))
            .collect_vec();
        drop(prune_guard);
        let prev_sink = prev_state.ghostdag_data.selected_parent;
        let mut accumulated_diff = prev_state.utxo_diff.clone().to_reversed();
        if !self.ensure_current_atomic_store_matches_virtual(&virtual_read, &prev_state) {
            return;
        }
        let mut accumulated_atomic_state = self.atomic_state_store.attach_virtual_state(&prev_state.atomic_state);
        if let Err(err) = accumulated_atomic_state.apply_delta_rollback(&prev_state.atomic_diff) {
            warn!("failed rolling back virtual Atomic diff for previous sink `{prev_sink}`: {err}; keeping previous virtual state");
            return;
        }

        let (new_sink, virtual_parent_candidates) = self.sink_search_algorithm(
            &virtual_read,
            &mut accumulated_diff,
            &mut accumulated_atomic_state,
            prev_sink,
            tips,
            finality_point,
            pruning_point,
        );
        let (virtual_parents, virtual_ghostdag_data) = self.pick_virtual_parents(new_sink, virtual_parent_candidates, pruning_point);
        assert_eq!(virtual_ghostdag_data.selected_parent, new_sink);

        if new_sink == prev_sink && virtual_parents == prev_state.parents {
            // A block can be processed and then disqualified without changing the selected
            // virtual view. In that case, keep the previous virtual UTXO/Atomic state as-is.
            return;
        }

        let sink_multiset = self.utxo_multisets_store.get(new_sink).unwrap();
        let chain_path = self.dag_traversal_manager.calculate_chain_path(prev_sink, new_sink, None);
        let new_virtual_state = self
            .calculate_and_commit_virtual_state(
                virtual_read,
                virtual_parents,
                virtual_ghostdag_data,
                sink_multiset,
                &mut accumulated_diff,
                accumulated_atomic_state,
                &chain_path,
            )
            .expect("all possible rule errors are unexpected here");

        self.log_atomic_consensus_state_summary("virtual_update", &new_virtual_state);

        // Update the pruning processor about the virtual state change
        let sink_ghostdag_data = self.ghostdag_primary_store.get_compact_data(new_sink).unwrap();
        // Empty the channel before sending the new message. If pruning processor is busy, this step makes sure
        // the internal channel does not grow with no need (since we only care about the most recent message)
        let _consume = self.pruning_receiver.try_iter().count();
        self.pruning_sender.send(PruningProcessingMessage::Process { sink_ghostdag_data }).unwrap();

        // Emit notifications
        let accumulated_diff = Arc::new(accumulated_diff);
        let virtual_parents = Arc::new(new_virtual_state.parents.clone());
        self.notification_root
            .notify(Notification::NewBlockTemplate(NewBlockTemplateNotification {}))
            .expect("expecting an open unbounded channel");
        self.notification_root
            .notify(Notification::UtxosChanged(UtxosChangedNotification::new(accumulated_diff, virtual_parents)))
            .expect("expecting an open unbounded channel");
        self.notification_root
            .notify(Notification::SinkBlueScoreChanged(SinkBlueScoreChangedNotification::new(sink_ghostdag_data.blue_score)))
            .expect("expecting an open unbounded channel");
        self.notification_root
            .notify(Notification::VirtualDaaScoreChanged(VirtualDaaScoreChangedNotification::new(new_virtual_state.daa_score)))
            .expect("expecting an open unbounded channel");
        if self.notification_root.has_subscription(EventType::VirtualChainChanged) {
            // check for subscriptions before the heavy lifting
            let added_chain_blocks_acceptance_data =
                chain_path.added.iter().copied().map(|added| self.acceptance_data_store.get(added).unwrap()).collect_vec();
            self.notification_root
                .notify(Notification::VirtualChainChanged(VirtualChainChangedNotification::new(
                    chain_path.added.into(),
                    chain_path.removed.into(),
                    Arc::new(added_chain_blocks_acceptance_data),
                )))
                .expect("expecting an open unbounded channel");
        }
    }

    pub(crate) fn virtual_finality_point(&self, virtual_ghostdag_data: &GhostdagData, pruning_point: Hash) -> Hash {
        let finality_point = self.depth_manager.calc_finality_point(virtual_ghostdag_data, pruning_point);
        if self.reachability_service.is_chain_ancestor_of(pruning_point, finality_point) {
            finality_point
        } else {
            // At the beginning of IBD when virtual finality point might be below the pruning point
            // or disagreeing with the pruning point chain, we take the pruning point itself as the finality point
            pruning_point
        }
    }

    /// Calculates the UTXO state of `to` starting from the state of `from`.
    /// The provided `diff` is assumed to initially hold the UTXO diff of `from` from virtual.
    /// The function returns the top-most UTXO-valid block on `chain(to)` which is ideally
    /// `to` itself (with the exception of returning `from` if `to` is already known to be UTXO disqualified).
    /// When returning it is guaranteed that `diff` holds the diff of the returned block from virtual
    fn calculate_utxo_state_relatively(
        &self,
        stores: &VirtualStores,
        diff: &mut UtxoDiff,
        atomic_state: &mut AtomicConsensusState,
        from: Hash,
        to: Hash,
    ) -> Hash {
        // Avoid reorging if disqualified status is already known
        if self.statuses_store.read().get(to).unwrap() == StatusDisqualifiedFromChain {
            return from;
        }

        let mut split_point: Option<Hash> = None;

        let mut missing_pre_hf_atomic_delta = false;

        // Walk down to the reorg split point
        for current in self.reachability_service.default_backward_chain_iterator(from) {
            if self.reachability_service.is_chain_ancestor_of(current, to) {
                split_point = Some(current);
                break;
            }

            let mergeset_diff = self.utxo_diffs_store.get(current).unwrap();
            // Apply the diff in reverse
            diff.with_diff_in_place(&mergeset_diff.as_reversed()).unwrap();
            match self.atomic_state_store.get_delta(current) {
                Ok(delta) => {
                    if let Err(err) = atomic_state.apply_delta_rollback(delta.as_ref()) {
                        warn!("failed rolling back atomic delta for block `{current}`: {err}; keeping previous virtual sink");
                        return from;
                    }
                }
                Err(StoreError::KeyNotFound(_)) => {
                    let block_daa_score = self.headers_store.get_header(current).unwrap().daa_score;
                    if self.transaction_validator.is_payload_hf_active(block_daa_score) {
                        warn!("missing persisted atomic delta for post-HF block `{current}`; keeping previous virtual sink");
                        return from;
                    }
                    missing_pre_hf_atomic_delta = true;
                }
                Err(err) => {
                    warn!("failed reading atomic delta for block `{current}`: {err}; keeping previous virtual sink");
                    return from;
                }
            }
        }

        let split_point = split_point.expect("chain iterator was expected to reach the reorg split point");
        debug!("VIRTUAL PROCESSOR, found split point: {split_point}");
        if missing_pre_hf_atomic_delta {
            let Some(split_point_state) = self.pre_hf_atomic_state_from_virtual_diff(stores, diff, split_point) else {
                warn!(
                    "cannot resolve virtual state because split point `{split_point}` has no reconstructable pre-HF atomic state; keeping previous virtual sink"
                );
                return from;
            };
            *atomic_state = split_point_state;
        }
        atomic_state.rebuild_liquidity_vault_outpoint_index();

        // A variable holding the most recent UTXO-valid block on `chain(to)` (note that it's maintained such
        // that 'diff' is always its UTXO diff from virtual)
        let mut diff_point = split_point;

        // Walk back up to the new virtual selected parent candidate
        let mut chain_block_counter = 0;
        let mut chain_disqualified_counter = 0;
        let mut logged_disqualified_parent_propagation = false;
        for (selected_parent, current) in self.reachability_service.forward_chain_iterator(split_point, to, true).tuple_windows() {
            if selected_parent != diff_point {
                // This indicates that the selected parent is disqualified, propagate up and continue
                if self.statuses_store.read().get(current).unwrap() != StatusDisqualifiedFromChain {
                    if !logged_disqualified_parent_propagation {
                        let current_daa = self.headers_store.get_header(current).map(|h| h.daa_score).unwrap_or_default();
                        warn!(
                            "Disqualifying selected-chain block(s) because selected parent is already disqualified: first_child={}, selected_parent={}, last_valid_diff_point={}, current_daa={}, target_tip={}",
                            current, selected_parent, diff_point, current_daa, to
                        );
                        logged_disqualified_parent_propagation = true;
                    }
                    self.mark_block_disqualified(current);
                    chain_disqualified_counter += 1;
                }
                continue;
            }

            if self.statuses_store.read().get(current).unwrap() == StatusDisqualifiedFromChain {
                // Disqualified blocks may still have cached UTXO/Atomic diffs from before
                // disqualification. Never replay those caches into the live virtual state.
                continue;
            }

            let mut needs_recompute = true;
            match self.utxo_diffs_store.get(current) {
                Ok(mergeset_diff) => match self.atomic_state_store.get_delta(current) {
                    Ok(delta) => {
                        if let Err(err) = atomic_state.apply_delta_forward(delta.as_ref()) {
                            warn!("block `{current}` has cached UTXO diff but invalid atomic delta ({err}); recomputing");
                        } else {
                            diff.with_diff_in_place(mergeset_diff.deref()).unwrap();
                            diff_point = current;
                            needs_recompute = false;
                        }
                    }
                    Err(StoreError::KeyNotFound(_)) => {
                        warn!("block `{current}` has cached UTXO diff but no atomic delta; recomputing block UTXO/atomic state");
                    }
                    Err(err) => panic!("unexpected error {err}"),
                },
                Err(StoreError::KeyNotFound(_)) => {}
                Err(err) => panic!("unexpected error {err}"),
            }
            if !needs_recompute {
                continue;
            }

            let header = self.headers_store.get_header(current).unwrap();
            let mergeset_data = self.ghostdag_primary_store.get_data(current).unwrap();
            let pov_daa_score = header.daa_score;

            let selected_parent_multiset_hash = self.utxo_multisets_store.get(selected_parent).unwrap();
            let selected_parent_utxo_view = (&stores.utxo_set).compose(&*diff);

            let mut ctx = UtxoProcessingContext::new(mergeset_data.into(), selected_parent_multiset_hash, atomic_state.clone());

            self.calculate_utxo_state(&mut ctx, &selected_parent_utxo_view, pov_daa_score);
            let res = self.verify_expected_utxo_state(&mut ctx, &selected_parent_utxo_view, &header);

            if let Err(rule_error) = res {
                let txs = self.block_transactions_store.get(current).ok();
                let tx_count = txs.as_ref().map(|txs| txs.len()).unwrap_or_default();
                let payload_tx_count =
                    txs.as_ref().map(|txs| txs.iter().filter(|tx| !tx.payload.is_empty()).count()).unwrap_or_default();
                warn!(
                    "Disqualifying block after UTXO/Atomic verification failed: block={}, selected_parent={}, daa={}, blue_score={}, txs={}, non_coinbase_txs={}, payload_txs={}, utxo_commitment={}, reason={}",
                    current,
                    selected_parent,
                    header.daa_score,
                    header.blue_score,
                    tx_count,
                    tx_count.saturating_sub(1),
                    payload_tx_count,
                    header.utxo_commitment,
                    rule_error
                );
                self.mark_block_disqualified(current);
                chain_disqualified_counter += 1;
            } else {
                debug!("VIRTUAL PROCESSOR, UTXO validated for {current}");

                // Accumulate the diff
                diff.with_diff_in_place(&ctx.mergeset_diff).unwrap();
                // Update the diff point
                diff_point = current;
                *atomic_state = ctx.atomic_state.clone();
                // Commit UTXO data for current chain block
                self.commit_utxo_state(current, ctx.mergeset_diff, ctx.multiset_hash, ctx.mergeset_acceptance_data, ctx.atomic_state);
                // Count the number of UTXO-processed chain blocks
                chain_block_counter += 1;
            }
        }
        // Report counters
        self.counters.chain_block_counts.fetch_add(chain_block_counter, Ordering::Relaxed);
        if chain_disqualified_counter > 0 {
            self.counters.chain_disqualified_counts.fetch_add(chain_disqualified_counter, Ordering::Relaxed);
        }

        diff_point
    }

    fn mark_block_disqualified(&self, block: Hash) {
        let replacement_tips = self.disqualified_tip_replacement_parents(block);
        let mut batch = WriteBatch::default();
        let status_write_guard = self.statuses_store.set_batch(&mut batch, block, StatusDisqualifiedFromChain).unwrap();
        let mut tips_write_guard = self.body_tips_store.write();
        tips_write_guard.update_tips_batch(&mut batch, &replacement_tips, &[block]).unwrap();
        self.db.write(batch).unwrap();
        drop(status_write_guard);
        drop(tips_write_guard);
    }

    fn sanitize_disqualified_body_tips(&self, fallback_tip: Hash) {
        let disqualified_tips = {
            let body_tips_read = self.body_tips_store.read();
            body_tips_read
                .get()
                .unwrap()
                .read()
                .iter()
                .copied()
                .filter(|&tip| self.statuses_store.read().get(tip).unwrap() == StatusDisqualifiedFromChain)
                .collect_vec()
        };

        let tips_are_empty = { self.body_tips_store.read().get().unwrap().read().is_empty() };
        if disqualified_tips.is_empty() && !tips_are_empty {
            return;
        }

        let mut replacement_tips =
            disqualified_tips.iter().copied().flat_map(|tip| self.disqualified_tip_replacement_parents(tip)).collect_vec();
        if tips_are_empty
            && self.statuses_store.read().get(fallback_tip).unwrap() != StatusDisqualifiedFromChain
            && self.relations_service.has(fallback_tip).unwrap_or(false)
        {
            replacement_tips.push(fallback_tip);
        }
        replacement_tips.sort_unstable();
        replacement_tips.dedup();

        if !disqualified_tips.is_empty() || tips_are_empty {
            warn!(
                "Consensus pruned disqualified body tip(s) before virtual resolve: removed={}, restored={}, fallback_tip={}, body_tips_empty={}",
                disqualified_tips.len(),
                replacement_tips.len(),
                fallback_tip,
                tips_are_empty
            );
        }

        let mut batch = WriteBatch::default();
        let mut tips_write_guard = self.body_tips_store.write();
        tips_write_guard.update_tips_batch(&mut batch, &replacement_tips, &disqualified_tips).unwrap();
        self.db.write(batch).unwrap();
        drop(tips_write_guard);
    }

    fn disqualified_tip_replacement_parents(&self, block: Hash) -> Vec<Hash> {
        let is_tip = {
            let body_tips_read = self.body_tips_store.read();
            body_tips_read.get().unwrap().read().contains(&block)
        };
        if !is_tip {
            return Vec::new();
        }

        self.relations_service
            .get_parents(block)
            .unwrap()
            .iter()
            .copied()
            .filter(|&parent| self.statuses_store.read().get(parent).unwrap() != StatusDisqualifiedFromChain)
            .filter(|&parent| self.all_body_children_disqualified(parent, block))
            .collect()
    }

    fn all_body_children_disqualified(&self, parent: Hash, pending_disqualified_child: Hash) -> bool {
        let children = match self.relations_service.get_children(parent) {
            Ok(children) => children,
            Err(StoreError::KeyNotFound(_)) => return false,
            Err(err) => panic!("unexpected error {err}"),
        };

        let all_children_disqualified = children.read().iter().copied().all(|child| {
            child == pending_disqualified_child || self.statuses_store.read().get(child).unwrap() == StatusDisqualifiedFromChain
        });
        all_children_disqualified
    }

    fn commit_utxo_state(
        &self,
        current: Hash,
        mergeset_diff: UtxoDiff,
        multiset: MuHash,
        acceptance_data: AcceptanceData,
        mut atomic_state: AtomicConsensusState,
    ) {
        let atomic_state_hash = atomic_state.canonical_hash();
        let atomic_delta = Arc::new(atomic_state.take_delta());
        let mut batch = WriteBatch::default();
        self.utxo_diffs_store.insert_batch(&mut batch, current, Arc::new(mergeset_diff)).unwrap();
        self.utxo_multisets_store.insert_batch(&mut batch, current, multiset).unwrap();
        self.acceptance_data_store.insert_batch(&mut batch, current, Arc::new(acceptance_data)).unwrap();
        self.atomic_state_store.insert_batch_with_delta(&mut batch, current, atomic_state_hash, atomic_delta).unwrap();
        let write_guard = self.statuses_store.set_batch(&mut batch, current, StatusUTXOValid).unwrap();
        self.db.write(batch).unwrap();
        // Calling the drops explicitly after the batch is written in order to avoid possible errors.
        drop(write_guard);
    }

    fn calculate_and_commit_virtual_state(
        &self,
        virtual_read: RwLockUpgradableReadGuard<'_, VirtualStores>,
        virtual_parents: Vec<Hash>,
        virtual_ghostdag_data: GhostdagData,
        selected_parent_multiset: MuHash,
        accumulated_diff: &mut UtxoDiff,
        selected_parent_atomic_state: AtomicConsensusState,
        chain_path: &ChainPath,
    ) -> Result<Arc<VirtualState>, RuleError> {
        let new_virtual_state = self.calculate_virtual_state(
            &virtual_read,
            virtual_parents,
            virtual_ghostdag_data,
            selected_parent_multiset,
            accumulated_diff,
            selected_parent_atomic_state,
        )?;
        self.commit_virtual_state(virtual_read, new_virtual_state.clone(), accumulated_diff, chain_path);
        Ok(new_virtual_state)
    }

    pub(super) fn calculate_virtual_state(
        &self,
        virtual_stores: &VirtualStores,
        virtual_parents: Vec<Hash>,
        virtual_ghostdag_data: GhostdagData,
        selected_parent_multiset: MuHash,
        accumulated_diff: &mut UtxoDiff,
        selected_parent_atomic_state: AtomicConsensusState,
    ) -> Result<Arc<VirtualState>, RuleError> {
        let selected_parent_utxo_view = (&virtual_stores.utxo_set).compose(&*accumulated_diff);
        let mut ctx =
            UtxoProcessingContext::new((&virtual_ghostdag_data).into(), selected_parent_multiset, selected_parent_atomic_state);

        // Calc virtual DAA score, difficulty bits and past median time
        let virtual_daa_window = self.window_manager.block_daa_window(&virtual_ghostdag_data)?;
        let virtual_bits = self.window_manager.calculate_difficulty_bits(&virtual_ghostdag_data, &virtual_daa_window);
        let virtual_past_median_time = self.window_manager.calc_past_median_time(&virtual_ghostdag_data)?.0;

        // Calc virtual UTXO state relative to selected parent
        self.calculate_utxo_state(&mut ctx, &selected_parent_utxo_view, virtual_daa_window.daa_score);

        // Update the accumulated diff
        accumulated_diff.with_diff_in_place(&ctx.mergeset_diff).unwrap();

        let atomic_diff = ctx.atomic_state.take_delta();

        // Build the new virtual state
        Ok(Arc::new(VirtualState::new(
            virtual_parents,
            virtual_daa_window.daa_score,
            virtual_bits,
            virtual_past_median_time,
            ctx.multiset_hash,
            ctx.mergeset_diff,
            ctx.accepted_tx_ids,
            ctx.mergeset_rewards,
            virtual_daa_window.mergeset_non_daa,
            atomic_diff,
            ctx.atomic_state,
            virtual_ghostdag_data,
        )))
    }

    pub(crate) fn rebuild_virtual_state_for_startup_repair(
        &self,
        target: Hash,
        target_index: u64,
    ) -> Result<Arc<VirtualState>, String> {
        let virtual_read = self.virtual_stores.upgradable_read();
        let prev_state =
            virtual_read.state.get().map_err(|err| format!("startup repair failed reading previous virtual state: {err}"))?;
        let prev_sink = prev_state.ghostdag_data.selected_parent;

        let mut accumulated_diff = prev_state.utxo_diff.clone().to_reversed();
        if prev_sink != target {
            if !self.reachability_service.is_chain_ancestor_of(target, prev_sink) {
                return Err(format!(
                    "startup repair target `{target}` is not a chain ancestor of previous virtual selected parent `{prev_sink}`"
                ));
            }

            for current in self.reachability_service.default_backward_chain_iterator(prev_sink) {
                if current == target {
                    break;
                }
                let mergeset_diff = self
                    .utxo_diffs_store
                    .get(current)
                    .map_err(|err| format!("startup repair failed reading UTXO diff for `{current}`: {err}"))?;
                accumulated_diff
                    .with_diff_in_place(&mergeset_diff.as_reversed())
                    .map_err(|err| format!("startup repair failed rolling back UTXO diff for `{current}`: {err}"))?;
            }
        }

        let selected_parent_atomic_state = self.atomic_state_for_selected_chain_prefix(target_index, target)?;
        let virtual_parents = vec![target];
        let virtual_ghostdag_data = self.ghostdag_manager.ghostdag(&virtual_parents);
        let selected_parent_multiset = self
            .utxo_multisets_store
            .get(target)
            .map_err(|err| format!("startup repair failed reading target UTXO multiset for `{target}`: {err}"))?;
        let new_virtual_state = self
            .calculate_virtual_state(
                &virtual_read,
                virtual_parents,
                virtual_ghostdag_data,
                selected_parent_multiset,
                &mut accumulated_diff,
                selected_parent_atomic_state,
            )
            .map_err(|err| format!("startup repair failed calculating repaired virtual state for `{target}`: {err}"))?;

        self.commit_startup_repair_virtual_state(virtual_read, new_virtual_state.clone(), &accumulated_diff)?;
        self.log_atomic_consensus_state_summary("startup_repair", &new_virtual_state);
        Ok(new_virtual_state)
    }

    fn atomic_state_for_selected_chain_prefix(&self, target_index: u64, target: Hash) -> Result<AtomicConsensusState, String> {
        let selected_chain_read = self.selected_chain_store.read();
        let actual_target = selected_chain_read
            .get_by_index(target_index)
            .map_err(|err| format!("startup repair target selected-chain index `{target_index}` unavailable: {err}"))?;
        if actual_target != target {
            return Err(format!(
                "startup repair target mismatch at selected-chain index `{target_index}`: expected `{target}`, got `{actual_target}`"
            ));
        }

        let base_hash = selected_chain_read
            .get_by_index(0)
            .map_err(|err| format!("startup repair selected-chain base block unavailable: {err}"))?;
        if base_hash != self.genesis.hash {
            return Err(format!(
                "startup repair Atomic replay starts at non-genesis base `{base_hash}`; import a full Atomic snapshot or rewind to an archive-backed chain before repairing"
            ));
        }

        let mut state = AtomicConsensusState::default();
        let mut replayed_blocks = 0u64;
        let mut replayed_transactions = 0u64;
        for index in 1..=target_index {
            let block_hash = selected_chain_read
                .get_by_index(index)
                .map_err(|err| format!("startup repair selected-chain index `{index}` unavailable: {err}"))?;
            match self.atomic_state_store.get_delta(block_hash) {
                Ok(delta) => state
                    .apply_delta_forward(delta.as_ref())
                    .map_err(|err| format!("startup repair failed replaying Atomic delta for `{block_hash}`: {err}"))?,
                Err(StoreError::KeyNotFound(_)) => {
                    let pov_daa_score = self
                        .headers_store
                        .get_header(block_hash)
                        .map_err(|err| format!("startup repair selected-chain block `{block_hash}` header unavailable: {err}"))?
                        .daa_score;
                    state.begin_delta_tracking();
                    let accepted = self.replay_atomic_acceptance_for_block(block_hash, pov_daa_score, &mut state)?;
                    let _ = state.take_delta();
                    replayed_transactions += accepted;
                }
                Err(err) => return Err(format!("startup repair failed reading Atomic delta for `{block_hash}`: {err}")),
            }
            replayed_blocks += 1;
            if replayed_blocks % 10_000 == 0 {
                info!(
                    "startup repair Atomic selected-chain replay progress: {}/{} block(s), {} accepted non-coinbase tx(s) replayed from local block data",
                    replayed_blocks, target_index, replayed_transactions
                );
            }
        }
        drop(selected_chain_read);

        let state_hash = state.canonical_hash();
        match self.atomic_state_store.get_root_record(target) {
            Ok(root) if root.state_hash != state_hash => {
                return Err(format!(
                    "startup repair replayed Atomic root for `{target}` does not match persisted root: replayed={}, persisted={}",
                    faster_hex::hex_string(&state_hash),
                    faster_hex::hex_string(&root.state_hash)
                ));
            }
            Ok(_) | Err(StoreError::KeyNotFound(_)) => {}
            Err(err) => return Err(format!("startup repair failed reading Atomic root for `{target}`: {err}")),
        }

        Ok(state)
    }

    fn commit_startup_repair_virtual_state(
        &self,
        virtual_read: RwLockUpgradableReadGuard<'_, VirtualStores>,
        new_virtual_state: Arc<VirtualState>,
        accumulated_diff: &UtxoDiff,
    ) -> Result<(), String> {
        let mut batch = WriteBatch::default();
        let mut virtual_write = RwLockUpgradableReadGuard::upgrade(virtual_read);

        virtual_write
            .utxo_set
            .write_diff_batch(&mut batch, accumulated_diff)
            .map_err(|err| format!("startup repair failed writing repaired virtual UTXO diff: {err}"))?;
        self.atomic_state_store
            .replace_current_overlay_batch(&mut batch, &new_virtual_state.atomic_state)
            .map_err(|err| format!("startup repair failed writing repaired Atomic current state: {err}"))?;

        let mut compact_virtual_state = new_virtual_state.as_ref().clone();
        compact_virtual_state.atomic_state = compact_virtual_state.atomic_state.as_virtual_root_state();
        let compact_virtual_state = Arc::new(compact_virtual_state);
        let new_virtual_daa_score = compact_virtual_state.daa_score;
        virtual_write
            .state
            .set_batch(&mut batch, compact_virtual_state)
            .map_err(|err| format!("startup repair failed writing repaired virtual state: {err}"))?;

        self.db.write(batch).map_err(|err| format!("startup repair failed committing repaired virtual state: {err}"))?;
        self.counters.virtual_daa_score.store(new_virtual_daa_score, Ordering::Relaxed);
        Ok(())
    }

    fn commit_virtual_state(
        &self,
        virtual_read: RwLockUpgradableReadGuard<'_, VirtualStores>,
        new_virtual_state: Arc<VirtualState>,
        accumulated_diff: &UtxoDiff,
        chain_path: &ChainPath,
    ) {
        let mut batch = WriteBatch::default();
        let mut virtual_write = RwLockUpgradableReadGuard::upgrade(virtual_read);
        let mut selected_chain_write = self.selected_chain_store.write();

        // Apply the accumulated diff to the virtual UTXO set
        virtual_write.utxo_set.write_diff_batch(&mut batch, accumulated_diff).unwrap();

        self.atomic_state_store.write_current_overlay_batch(&mut batch, &new_virtual_state.atomic_state).unwrap();

        let mut compact_virtual_state = new_virtual_state.as_ref().clone();
        compact_virtual_state.atomic_state = compact_virtual_state.atomic_state.as_virtual_root_state();
        let new_virtual_state = Arc::new(compact_virtual_state);
        let new_virtual_daa_score = new_virtual_state.daa_score;

        // Update virtual state
        virtual_write.state.set_batch(&mut batch, new_virtual_state).unwrap();

        // Update the virtual selected chain
        selected_chain_write.apply_changes(&mut batch, chain_path).unwrap();

        // Flush the batch changes
        self.db.write(batch).unwrap();
        self.counters.virtual_daa_score.store(new_virtual_daa_score, Ordering::Relaxed);

        // Calling the drops explicitly after the batch is written in order to avoid possible errors.
        drop(virtual_write);
        drop(selected_chain_write);
    }

    fn log_atomic_consensus_state_summary(&self, reason: &str, virtual_state: &VirtualState) {
        let root_accumulator = virtual_state.atomic_state.root_accumulator();
        let summary = AtomicConsensusLogSummary {
            root: virtual_state.atomic_state.canonical_hash(),
            root_only: virtual_state.atomic_state.is_root_only(),
            assets: root_accumulator.asset_count(),
            balances: root_accumulator.balance_count(),
            nonces: root_accumulator.nonce_count(),
            anchors: root_accumulator.anchor_count(),
            vaults: virtual_state.atomic_state.materialized_vault_count(),
        };

        let now = Instant::now();
        let mut log_state = self.atomic_consensus_log_state.lock();
        let interval_elapsed =
            log_state.last_log_at.map(|last| now.duration_since(last) >= ATOMIC_CONSENSUS_LOG_INTERVAL).unwrap_or(true);
        if !interval_elapsed {
            return;
        }
        log_state.last_log_at = Some(now);
        drop(log_state);

        let vaults = match summary.vaults {
            Some(vaults) => vaults.to_string(),
            None if summary.root_only => {
                match self.atomic_state_store.current_vault_index_count_limited(ATOMIC_CONSENSUS_VAULT_LOG_COUNT_LIMIT) {
                    Ok(Some(vaults)) => vaults.to_string(),
                    Ok(None) => format!(">{}", ATOMIC_CONSENSUS_VAULT_LOG_COUNT_LIMIT),
                    Err(err) => format!("unknown_store_error:{err}"),
                }
            }
            None => "unknown".to_string(),
        };
        info!(
            "[atomic] Atomic consensus state: local_state=consistent consensus_correct=true reason={} daa={} hf_active={} root={} root_only={} assets={} balances={} nonces={} anchors={} vaults={} selected_parent={} parents={} utxo_add={} utxo_remove={}",
            reason,
            virtual_state.daa_score,
            self.transaction_validator.is_payload_hf_active(virtual_state.daa_score),
            faster_hex::hex_string(&summary.root),
            summary.root_only,
            summary.assets,
            summary.balances,
            summary.nonces,
            summary.anchors,
            vaults,
            virtual_state.ghostdag_data.selected_parent,
            virtual_state.parents.len(),
            virtual_state.utxo_diff.added().len(),
            virtual_state.utxo_diff.removed().len(),
        );
    }

    fn log_current_atomic_consensus_state(&self, reason: &str) {
        let virtual_read = self.virtual_stores.read();
        match virtual_read.state.get() {
            Ok(virtual_state) => self.log_atomic_consensus_state_summary(reason, &virtual_state),
            Err(err) => warn!("failed reading virtual state for Atomic consensus status log: {err}"),
        }
    }

    /// Returns the max number of tips to consider as virtual parents in a single virtual resolve operation.
    ///
    /// Guaranteed to be `>= self.max_block_parents`
    fn max_virtual_parent_candidates(&self) -> usize {
        // Limit to max_block_parents x 3 candidates. This way we avoid going over thousands of tips when the network isn't healthy.
        // There's no specific reason for a factor of 3, and its not a consensus rule, just an estimation for reducing the amount
        // of candidates considered.
        self.max_block_parents as usize * 3
    }

    /// Searches for the next valid sink block (SINK = Virtual selected parent). The search is performed
    /// in the inclusive past of `tips`.
    /// The provided `diff` is assumed to initially hold the UTXO diff of `prev_sink` from virtual.
    /// The function returns with `diff` being the diff of the new sink from previous virtual.
    /// In addition to the found sink the function also returns a queue of additional virtual
    /// parent candidates ordered in descending blue work order.
    pub(super) fn sink_search_algorithm(
        &self,
        stores: &VirtualStores,
        diff: &mut UtxoDiff,
        atomic_state: &mut AtomicConsensusState,
        prev_sink: Hash,
        tips: Vec<Hash>,
        finality_point: Hash,
        pruning_point: Hash,
    ) -> (Hash, VecDeque<Hash>) {
        // TODO (relaxed): additional tests

        let mut heap = tips
            .into_iter()
            .map(|block| SortableBlock { hash: block, blue_work: self.ghostdag_primary_store.get_blue_work(block).unwrap() })
            .collect::<BinaryHeap<_>>();

        // The initial diff point is the previous sink
        let mut diff_point = prev_sink;

        // We maintain the following invariant: `heap` is an antichain.
        // It holds at step 0 since tips are an antichain, and remains through the loop
        // since we check that every pushed block is not in the past of current heap
        // (and it can't be in the future by induction)
        loop {
            let candidate = heap.pop().expect("valid sink must exist").hash;
            if self.reachability_service.is_chain_ancestor_of(finality_point, candidate) {
                diff_point = self.calculate_utxo_state_relatively(stores, diff, atomic_state, diff_point, candidate);
                if diff_point == candidate {
                    // This indicates that candidate has valid UTXO state and that `diff` represents its diff from virtual

                    // All blocks with lower blue work than filtering_root are:
                    // 1. not in its future (bcs blue work is monotonic),
                    // 2. will be removed eventually by the bounded merge check.
                    // Hence as an optimization we prefer removing such blocks in advance to allow valid tips to be considered.
                    let filtering_root = self.depth_store.merge_depth_root(candidate).unwrap();
                    let filtering_blue_work = self.ghostdag_primary_store.get_blue_work(filtering_root).unwrap_or_default();
                    return (
                        candidate,
                        heap.into_sorted_iter().take_while(|s| s.blue_work >= filtering_blue_work).map(|s| s.hash).collect(),
                    );
                } else {
                    debug!("Block candidate {} has invalid UTXO state and is ignored from Virtual chain.", candidate)
                }
            } else if finality_point != pruning_point {
                // `finality_point == pruning_point` indicates we are at IBD start hence no warning required
                warn!("Finality Violation Detected. Block {} violates finality and is ignored from Virtual chain.", candidate);
            }
            // PRUNE SAFETY: see comment within [`resolve_virtual`]
            let prune_guard = self.pruning_lock.blocking_read();
            for parent in self.relations_service.get_parents(candidate).unwrap().iter().copied() {
                if self.reachability_service.is_dag_ancestor_of(finality_point, parent)
                    && !self.reachability_service.is_dag_ancestor_of_any(parent, &mut heap.iter().map(|sb| sb.hash))
                {
                    heap.push(SortableBlock { hash: parent, blue_work: self.ghostdag_primary_store.get_blue_work(parent).unwrap() });
                }
            }
            drop(prune_guard);
        }
    }

    /// Picks the virtual parents according to virtual parent selection pruning constrains.
    /// Assumes:
    ///     1. `selected_parent` is a UTXO-valid block
    ///     2. `candidates` are an antichain ordered in descending blue work order
    ///     3. `candidates` do not contain `selected_parent` and `selected_parent.blue work > max(candidates.blue_work)`  
    pub(super) fn pick_virtual_parents(
        &self,
        selected_parent: Hash,
        mut candidates: VecDeque<Hash>,
        pruning_point: Hash,
    ) -> (Vec<Hash>, GhostdagData) {
        // TODO (relaxed): additional tests

        // Mergeset increasing might traverse DAG areas which are below the finality point and which theoretically
        // can borderline with pruned data, hence we acquire the prune lock to ensure data consistency. Note that
        // the final selected mergeset can never be pruned (this is the essence of the prunality proof), however
        // we might touch such data prior to validating the bounded merge rule. All in all, this function is short
        // enough so we avoid making further optimizations
        let _prune_guard = self.pruning_lock.blocking_read();
        let max_block_parents = self.max_block_parents as usize;
        let max_candidates = self.max_virtual_parent_candidates();

        // Prioritize half the blocks with highest blue work and pick the rest randomly to ensure diversity between nodes
        if candidates.len() > max_candidates {
            // make_contiguous should be a no op since the deque was just built
            let slice = candidates.make_contiguous();

            // Keep slice[..max_block_parents / 2] as is, choose max_candidates - max_block_parents / 2 in random
            // from the remainder of the slice while swapping them to slice[max_block_parents / 2..max_candidates].
            //
            // Inspired by rand::partial_shuffle (which lacks the guarantee on chosen elements location).
            for i in max_block_parents / 2..max_candidates {
                let j = rand::thread_rng().gen_range(i..slice.len()); // i < max_candidates < slice.len()
                slice.swap(i, j);
            }

            // Truncate the unchosen elements
            candidates.truncate(max_candidates);
        } else if candidates.len() > max_block_parents / 2 {
            // Fallback to a simpler algo in this case
            candidates.make_contiguous()[max_block_parents / 2..].shuffle(&mut rand::thread_rng());
        }

        let mut virtual_parents = Vec::with_capacity(min(max_block_parents, candidates.len() + 1));
        virtual_parents.push(selected_parent);
        let mut mergeset_size = 1; // Count the selected parent

        // Try adding parents as long as mergeset size and number of parents limits are not reached
        while let Some(candidate) = candidates.pop_front() {
            if self.statuses_store.read().get(candidate).unwrap() == StatusDisqualifiedFromChain {
                debug!("Skipping disqualified virtual parent candidate {candidate}");
                continue;
            }
            if mergeset_size >= self.mergeset_size_limit || virtual_parents.len() >= max_block_parents {
                break;
            }
            match self.mergeset_increase(&virtual_parents, candidate, self.mergeset_size_limit - mergeset_size) {
                MergesetIncreaseResult::Accepted { increase_size } => {
                    mergeset_size += increase_size;
                    virtual_parents.push(candidate);
                }
                MergesetIncreaseResult::Rejected { new_candidate } => {
                    if self.statuses_store.read().get(new_candidate).unwrap() == StatusDisqualifiedFromChain {
                        debug!("Skipping disqualified replacement virtual parent candidate {new_candidate}");
                        continue;
                    }
                    // If we already have a candidate in the past of new candidate then skip.
                    if self.reachability_service.is_any_dag_ancestor(&mut candidates.iter().copied(), new_candidate) {
                        continue; // TODO (optimization): not sure this check is needed if candidates invariant as antichain is kept
                    }
                    // Remove all candidates which are in the future of the new candidate
                    candidates.retain(|&h| !self.reachability_service.is_dag_ancestor_of(new_candidate, h));
                    candidates.push_back(new_candidate);
                }
            }
        }
        assert!(mergeset_size <= self.mergeset_size_limit);
        assert!(virtual_parents.len() <= max_block_parents);
        self.remove_bounded_merge_breaking_parents(virtual_parents, pruning_point)
    }

    fn mergeset_increase(&self, selected_parents: &[Hash], candidate: Hash, budget: u64) -> MergesetIncreaseResult {
        /*
        Algo:
            Traverse past(candidate) \setminus past(selected_parents) and make
            sure the increase in mergeset size is within the available budget
        */

        let candidate_parents = self.relations_service.get_parents(candidate).unwrap();
        let mut queue: VecDeque<_> = candidate_parents.iter().copied().collect();
        let mut visited: BlockHashSet = queue.iter().copied().collect();
        let mut mergeset_increase = 1u64; // Starts with 1 to count for the candidate itself

        while let Some(current) = queue.pop_front() {
            if self.reachability_service.is_dag_ancestor_of_any(current, &mut selected_parents.iter().copied()) {
                continue;
            }
            mergeset_increase += 1;
            if mergeset_increase > budget {
                return MergesetIncreaseResult::Rejected { new_candidate: current };
            }

            let current_parents = self.relations_service.get_parents(current).unwrap();
            for &parent in current_parents.iter() {
                if visited.insert(parent) {
                    queue.push_back(parent);
                }
            }
        }
        MergesetIncreaseResult::Accepted { increase_size: mergeset_increase }
    }

    fn remove_bounded_merge_breaking_parents(
        &self,
        mut virtual_parents: Vec<Hash>,
        current_pruning_point: Hash,
    ) -> (Vec<Hash>, GhostdagData) {
        let mut ghostdag_data = self.ghostdag_manager.ghostdag(&virtual_parents);
        let merge_depth_root = self.depth_manager.calc_merge_depth_root(&ghostdag_data, current_pruning_point);
        let mut kosherizing_blues: Option<Vec<Hash>> = None;
        let mut bad_reds = Vec::new();

        //
        // Note that the code below optimizes for the usual case where there are no merge-bound-violating blocks.
        //

        // Find red blocks violating the merge bound and which are not kosherized by any blue
        for red in ghostdag_data.mergeset_reds.iter().copied() {
            if self.reachability_service.is_dag_ancestor_of(merge_depth_root, red) {
                continue;
            }
            // Lazy load the kosherizing blocks since this case is extremely rare
            if kosherizing_blues.is_none() {
                kosherizing_blues = Some(self.depth_manager.kosherizing_blues(&ghostdag_data, merge_depth_root).collect());
            }
            if !self.reachability_service.is_dag_ancestor_of_any(red, &mut kosherizing_blues.as_ref().unwrap().iter().copied()) {
                bad_reds.push(red);
            }
        }

        if !bad_reds.is_empty() {
            // Remove all parents which lead to merging a bad red
            virtual_parents.retain(|&h| !self.reachability_service.is_any_dag_ancestor(&mut bad_reds.iter().copied(), h));
            // Recompute ghostdag data since parents changed
            ghostdag_data = self.ghostdag_manager.ghostdag(&virtual_parents);
        }

        (virtual_parents, ghostdag_data)
    }

    fn atomic_state_for_virtual_context(&self, atomic_state: &AtomicConsensusState) -> AtomicConsensusState {
        if atomic_state.is_disk_backed() {
            atomic_state.clone()
        } else {
            self.atomic_state_store.attach_virtual_state(atomic_state)
        }
    }

    fn ensure_current_atomic_store_matches_virtual(&self, virtual_stores: &VirtualStores, virtual_state: &VirtualState) -> bool {
        let expected = virtual_state.atomic_state.root_accumulator();
        match self.atomic_state_store.read_current_root() {
            Ok(Some(actual)) if actual == expected => return true,
            Ok(Some(actual)) => {
                warn!(
                    "Atomic V2 current-state root mismatch before virtual resolve: virtual={}, current={}; attempting local selected-chain rebuild",
                    faster_hex::hex_string(&AtomicConsensusState::root_only(expected).canonical_hash()),
                    faster_hex::hex_string(&AtomicConsensusState::root_only(actual).canonical_hash())
                );
            }
            Ok(None) if expected == Default::default() => return true,
            Ok(None) => {
                warn!(
                    "Atomic V2 current-state KV store is missing while virtual root is {}; attempting local selected-chain rebuild",
                    faster_hex::hex_string(&AtomicConsensusState::root_only(expected).canonical_hash())
                );
            }
            Err(err) => {
                warn!("failed reading Atomic V2 current-state root before virtual resolve: {err}; attempting local selected-chain rebuild");
            }
        }

        match self.rebuild_current_atomic_store_from_selected_chain(virtual_state) {
            Ok(()) => true,
            Err(err) => {
                warn!("cannot repair Atomic V2 current-state KV store from local selected-chain data: {err}; trying virtual UTXO reconstruction");
                match self.rebuild_current_atomic_store_from_virtual_utxo(virtual_stores, virtual_state) {
                    Ok(()) => true,
                    Err(err) => {
                        warn!("cannot repair Atomic V2 current-state KV store from virtual UTXO set: {err}; keeping previous virtual state");
                        false
                    }
                }
            }
        }
    }

    fn virtual_states_match_consensus_commitment_parts(current: &VirtualState, recalculated: &VirtualState) -> bool {
        current.parents == recalculated.parents
            && current.ghostdag_data.selected_parent == recalculated.ghostdag_data.selected_parent
            && current.ghostdag_data.blue_score == recalculated.ghostdag_data.blue_score
            && current.ghostdag_data.blue_work == recalculated.ghostdag_data.blue_work
            && current.daa_score == recalculated.daa_score
            && current.bits == recalculated.bits
            && current.past_median_time == recalculated.past_median_time
            && current.multiset.clone().finalize() == recalculated.multiset.clone().finalize()
            && current.utxo_diff == recalculated.utxo_diff
            && current.accepted_tx_ids == recalculated.accepted_tx_ids
            && current.mergeset_non_daa == recalculated.mergeset_non_daa
            && current.atomic_state.canonical_hash() == recalculated.atomic_state.canonical_hash()
            && current.atomic_diff == recalculated.atomic_diff
    }

    fn repair_virtual_state_from_selected_chain_if_inconsistent(&self, reason: &str) {
        let virtual_read = self.virtual_stores.upgradable_read();
        let Ok(virtual_state) = virtual_read.state.get() else {
            return;
        };

        let selected_parent = virtual_state.ghostdag_data.selected_parent;
        let Ok(selected_parent_multiset) = self.utxo_multisets_store.get(selected_parent) else {
            return;
        };

        let expected_root = virtual_state.atomic_state.root_accumulator();
        let can_attach_current = match self.atomic_state_store.read_current_root() {
            Ok(Some(actual)) => actual == expected_root,
            Ok(None) => expected_root == AtomicConsensusRootAccumulator::default(),
            Err(_) => false,
        };
        let self_consistent = if can_attach_current {
            let mut rollback_diff = virtual_state.utxo_diff.clone().to_reversed();
            let mut rollback_atomic = self.atomic_state_store.attach_virtual_state(&virtual_state.atomic_state);
            rollback_atomic
                .apply_delta_rollback(&virtual_state.atomic_diff)
                .ok()
                .and_then(|_| {
                    self.calculate_virtual_state(
                        &virtual_read,
                        virtual_state.parents.clone(),
                        virtual_state.ghostdag_data.clone(),
                        selected_parent_multiset.clone(),
                        &mut rollback_diff,
                        rollback_atomic,
                    )
                    .ok()
                })
                .is_some_and(|recalculated| Self::virtual_states_match_consensus_commitment_parts(&virtual_state, &recalculated))
        } else {
            false
        };

        if self_consistent {
            return;
        }

        let (tip_index, tip_hash) = match self.selected_chain_store.read().get_tip() {
            Ok(tip) => tip,
            Err(err) => {
                warn!("Virtual Atomic self-repair skipped before {reason}: selected-chain tip unavailable: {err}");
                return;
            }
        };
        if tip_hash != selected_parent {
            warn!(
                "Virtual Atomic self-repair skipped before {reason}: selected-chain tip {} does not match virtual selected parent {}",
                tip_hash, selected_parent
            );
            return;
        }

        let selected_parent_atomic_state = match self.atomic_state_for_selected_chain_prefix(tip_index, tip_hash) {
            Ok(state) => state,
            Err(err) => {
                warn!("Virtual Atomic self-repair skipped before {reason}: cannot reconstruct selected-parent Atomic prefix: {err}");
                return;
            }
        };

        let mut accumulated_diff = virtual_state.utxo_diff.clone().to_reversed();
        let repaired = match self.calculate_virtual_state(
            &virtual_read,
            virtual_state.parents.clone(),
            virtual_state.ghostdag_data.clone(),
            selected_parent_multiset,
            &mut accumulated_diff,
            selected_parent_atomic_state,
        ) {
            Ok(state) => state,
            Err(err) => {
                warn!("Virtual Atomic self-repair skipped before {reason}: recalculation failed: {err}");
                return;
            }
        };

        if Self::virtual_states_match_consensus_commitment_parts(&virtual_state, &repaired) {
            return;
        }

        warn!(
            "Repairing inconsistent virtual UTXO/Atomic state before {}: selected_parent={}, old_root={}, new_root={}",
            reason,
            selected_parent,
            faster_hex::hex_string(&virtual_state.atomic_state.canonical_hash()),
            faster_hex::hex_string(&repaired.atomic_state.canonical_hash())
        );
        self.commit_virtual_state(virtual_read, repaired, &accumulated_diff, &ChainPath::default());
    }

    fn ensure_virtual_parents_are_template_safe(&self, virtual_state: &VirtualState) -> Result<(), RuleError> {
        let selected_parent = virtual_state.ghostdag_data.selected_parent;
        let selected_parent_status = self.statuses_store.read().get(selected_parent).unwrap();
        if selected_parent_status != StatusUTXOValid {
            warn!(
                "Refusing block template because virtual selected parent is not UTXO-valid: selected_parent={}, status={:?}, daa={}, parents={}",
                selected_parent,
                selected_parent_status,
                virtual_state.daa_score,
                virtual_state.parents.len()
            );
            return Err(RuleError::KnownInvalid);
        }

        for parent in virtual_state.parents.iter().copied() {
            let status = self.statuses_store.read().get(parent).unwrap();
            match status {
                StatusInvalid | StatusDisqualifiedFromChain | StatusHeaderOnly => {
                    warn!(
                        "Refusing block template because virtual parent is not template-safe: parent={}, status={:?}, selected_parent={}, daa={}, parents={}",
                        parent,
                        status,
                        selected_parent,
                        virtual_state.daa_score,
                        virtual_state.parents.len()
                    );
                    return Err(RuleError::KnownInvalid);
                }
                StatusUTXOValid => {}
                // Non-selected merge parents can legitimately still be pending in a BlockDAG.
                _ => {}
            }
        }

        Ok(())
    }

    fn validate_mempool_transaction_impl(
        &self,
        mutable_tx: &mut MutableTransaction,
        virtual_state: &VirtualState,
        virtual_utxo_view: &impl UtxoView,
        virtual_daa_score: u64,
        virtual_past_median_time: u64,
        args: &TransactionValidationArgs,
    ) -> TxResult<()> {
        self.validate_mempool_transaction_without_atomic(
            mutable_tx,
            virtual_utxo_view,
            virtual_daa_score,
            virtual_past_median_time,
            args,
        )?;
        let mut atomic_state = self.atomic_state_for_virtual_context(&virtual_state.atomic_state);
        let mut atomic_growth = AtomicBlockStateGrowth::default();
        let creation_context = AtomicCreationContext {
            source_block_hash: Hash::from_bytes([0u8; 32]),
            source_block_daa_score: virtual_daa_score,
            source_block_time: virtual_past_median_time,
        };
        self.validate_and_apply_atomic_state_transition_with_growth(
            &mutable_tx.as_verifiable(),
            virtual_daa_score,
            creation_context,
            &mut atomic_state,
            &mut atomic_growth,
        )?;
        Ok(())
    }

    fn validate_mempool_transaction_without_atomic(
        &self,
        mutable_tx: &mut MutableTransaction,
        virtual_utxo_view: &impl UtxoView,
        virtual_daa_score: u64,
        virtual_past_median_time: u64,
        args: &TransactionValidationArgs,
    ) -> TxResult<()> {
        self.transaction_validator.validate_tx_in_isolation(&mutable_tx.tx, virtual_daa_score)?;
        self.transaction_validator.utxo_free_tx_validation(&mutable_tx.tx, virtual_daa_score, virtual_past_median_time)?;
        self.validate_mempool_transaction_in_utxo_context(mutable_tx, virtual_utxo_view, virtual_daa_score, args)?;
        Ok(())
    }

    fn extract_mempool_atomic_order_key(
        &self,
        mutable_tx: &MutableTransaction,
        virtual_daa_score: u64,
    ) -> TxResult<Option<AtomicTxOrderInfo>> {
        if !self.transaction_validator.is_payload_hf_active(virtual_daa_score) {
            return Ok(None);
        }

        let tx_ref = &mutable_tx.tx;
        if !tx_ref.subnetwork_id.is_payload() || tx_ref.payload.is_empty() {
            return Ok(None);
        }

        let Some(parsed_payload) = parse_atomic_payload(tx_ref.payload.as_slice()).map_err(TxRuleError::InvalidAtomicPayload)? else {
            return Ok(None);
        };

        let auth_input_index = parsed_payload.auth_input_index as usize;
        let verifiable = mutable_tx.as_verifiable();
        let (_, auth_entry) = verifiable.populated_inputs().nth(auth_input_index).ok_or_else(|| {
            TxRuleError::InvalidAtomicPayload(format!(
                "auth_input_index `{auth_input_index}` has no populated UTXO entry in contextual validation"
            ))
        })?;
        let owner_id = atomic_owner_id_from_script(&auth_entry.script_public_key).ok_or_else(|| {
            TxRuleError::InvalidAtomicPayload(
                "auth input script public key is not a supported CAT owner authorization scheme (expected PubKey, PubKeyECDSA, or ScriptHash)"
                    .to_string(),
            )
        })?;
        Ok(Some(Self::atomic_order_info_for_op(owner_id, parsed_payload.nonce, tx_ref.id().as_bytes(), &parsed_payload.op)))
    }

    fn extract_block_template_atomic_order_key<V: UtxoView>(
        &self,
        tx: &Transaction,
        utxo_view: &V,
        virtual_daa_score: u64,
    ) -> TxResult<Option<AtomicTxOrderInfo>> {
        if !self.transaction_validator.is_payload_hf_active(virtual_daa_score) {
            return Ok(None);
        }
        if !tx.subnetwork_id.is_payload() || tx.payload.is_empty() {
            return Ok(None);
        }

        let Some(parsed_payload) = parse_atomic_payload(tx.payload.as_slice()).map_err(TxRuleError::InvalidAtomicPayload)? else {
            return Ok(None);
        };

        let auth_input_index = parsed_payload.auth_input_index as usize;
        let auth_input = tx.inputs.get(auth_input_index).ok_or_else(|| {
            TxRuleError::InvalidAtomicPayload(format!(
                "auth_input_index `{auth_input_index}` has no transaction input in block-template ordering"
            ))
        })?;
        let auth_entry = utxo_view.get(&auth_input.previous_outpoint).ok_or(TxRuleError::MissingTxOutpoints)?;
        let owner_id = atomic_owner_id_from_script(&auth_entry.script_public_key).ok_or_else(|| {
            TxRuleError::InvalidAtomicPayload(
                "auth input script public key is not a supported CAT owner authorization scheme (expected PubKey, PubKeyECDSA, or ScriptHash)"
                    .to_string(),
            )
        })?;

        Ok(Some(Self::atomic_order_info_for_op(owner_id, parsed_payload.nonce, tx.id().as_bytes(), &parsed_payload.op)))
    }

    fn atomic_order_info_for_op(owner_id: [u8; 32], nonce: u64, txid_bytes: [u8; 32], op: &AtomicPayloadOp) -> AtomicTxOrderInfo {
        let nonce_key = atomic_nonce_key_for_op(owner_id, op);
        let pool = match op {
            AtomicPayloadOp::BuyLiquidityExactIn { asset_id, expected_pool_nonce, .. }
            | AtomicPayloadOp::SellLiquidityExactIn { asset_id, expected_pool_nonce, .. }
            | AtomicPayloadOp::ClaimLiquidityFees { asset_id, expected_pool_nonce, .. } => Some((*asset_id, *expected_pool_nonce)),
            _ => None,
        };
        let references_asset_id = match op {
            AtomicPayloadOp::Transfer { asset_id, .. }
            | AtomicPayloadOp::Mint { asset_id, .. }
            | AtomicPayloadOp::Burn { asset_id, .. }
            | AtomicPayloadOp::BuyLiquidityExactIn { asset_id, .. }
            | AtomicPayloadOp::SellLiquidityExactIn { asset_id, .. }
            | AtomicPayloadOp::ClaimLiquidityFees { asset_id, .. } => Some(*asset_id),
            _ => None,
        };
        let creates_asset_id = match op {
            AtomicPayloadOp::CreateAsset { .. }
            | AtomicPayloadOp::CreateAssetWithMint { .. }
            | AtomicPayloadOp::CreateLiquidityAsset { .. } => Some(txid_bytes),
            _ => None,
        };
        let (pool_asset_id, pool_nonce) = pool.unwrap_or(([0u8; 32], 0));
        AtomicTxOrderInfo {
            priority: AtomicTxOrderPriority { nonce_key, nonce, pool_asset_id, pool_nonce, txid_bytes },
            nonce_key,
            nonce,
            pool,
            creates_asset_id,
            references_asset_id,
        }
    }

    fn order_atomic_indices(atomic_items: &[(usize, AtomicTxOrderInfo)], atomic_state: &AtomicConsensusState) -> Vec<usize> {
        if atomic_items.len() <= 1 {
            return atomic_items.iter().map(|(idx, _)| *idx).collect();
        }

        let mut by_nonce: HashMap<(AtomicNonceKey, u64), Vec<usize>> = HashMap::new();
        let mut by_pool: HashMap<([u8; 32], u64), Vec<usize>> = HashMap::new();
        let mut by_created_asset: HashMap<[u8; 32], Vec<usize>> = HashMap::new();

        for (pos, (_idx, info)) in atomic_items.iter().enumerate() {
            by_nonce.entry((info.nonce_key, info.nonce)).or_default().push(pos);
            if let Some(pool) = info.pool {
                by_pool.entry(pool).or_default().push(pos);
            }
            if let Some(asset_id) = info.creates_asset_id {
                by_created_asset.entry(asset_id).or_default().push(pos);
            }
        }

        let mut dependents = vec![Vec::<usize>::new(); atomic_items.len()];
        let mut dependency_counts = vec![0usize; atomic_items.len()];
        let mut add_dependency = |parent: usize, child: usize| {
            dependents[parent].push(child);
            dependency_counts[child] += 1;
        };

        for (child_pos, (_, info)) in atomic_items.iter().enumerate() {
            let nonce_baseline = atomic_state.next_nonce(&info.nonce_key);
            if info.nonce > nonce_baseline {
                if let Some(previous_nonce) = info.nonce.checked_sub(1) {
                    if let Some(parents) = by_nonce.get(&(info.nonce_key, previous_nonce)) {
                        for parent in parents.iter().copied() {
                            add_dependency(parent, child_pos);
                        }
                    }
                }
            }

            if let Some((asset_id, pool_nonce)) = info.pool {
                let pool_baseline = atomic_state.pool_nonce(&asset_id);
                if pool_nonce > pool_baseline {
                    if let Some(previous_pool_nonce) = pool_nonce.checked_sub(1) {
                        if let Some(parents) = by_pool.get(&(asset_id, previous_pool_nonce)) {
                            for parent in parents.iter().copied() {
                                add_dependency(parent, child_pos);
                            }
                        }
                    }
                }
            }

            if let Some(asset_id) = info.references_asset_id {
                if !atomic_state.has_asset(&asset_id) {
                    if let Some(parents) = by_created_asset.get(&asset_id) {
                        for parent in parents.iter().copied() {
                            add_dependency(parent, child_pos);
                        }
                    }
                }
            }
        }

        let mut ready =
            dependency_counts.iter().enumerate().filter_map(|(pos, count)| (*count == 0).then_some(pos)).collect::<Vec<_>>();
        let mut emitted = vec![false; atomic_items.len()];
        let mut ordered_positions = Vec::with_capacity(atomic_items.len());

        while !ready.is_empty() {
            ready.sort_unstable_by(|a, b| atomic_items[*a].1.priority.cmp(&atomic_items[*b].1.priority));
            let pos = ready.remove(0);
            if emitted[pos] {
                continue;
            }
            emitted[pos] = true;
            ordered_positions.push(pos);

            let mut newly_ready = Vec::new();
            for child in dependents[pos].iter().copied() {
                dependency_counts[child] = dependency_counts[child].saturating_sub(1);
                if dependency_counts[child] == 0 {
                    newly_ready.push(child);
                }
            }
            ready.extend(newly_ready);
        }

        if ordered_positions.len() < atomic_items.len() {
            let mut remaining = (0..atomic_items.len()).filter(|pos| !emitted[*pos]).collect::<Vec<_>>();
            remaining.sort_unstable_by(|a, b| atomic_items[*a].1.priority.cmp(&atomic_items[*b].1.priority));
            ordered_positions.extend(remaining);
        }

        ordered_positions.into_iter().map(|pos| atomic_items[pos].0).collect()
    }

    fn order_block_template_transactions<V: UtxoView>(&self, txs: &mut Vec<Transaction>, virtual_state: &VirtualState, utxo_view: &V) {
        if txs.len() <= 1 {
            return;
        }

        let mut atomic_items = Vec::new();
        let mut non_atomic_indices = Vec::new();
        for (idx, tx) in txs.iter().enumerate() {
            match self.extract_block_template_atomic_order_key(tx, utxo_view, virtual_state.daa_score) {
                Ok(Some(info)) => atomic_items.push((idx, info)),
                Ok(None) | Err(_) => non_atomic_indices.push(idx),
            }
        }
        if atomic_items.len() <= 1 {
            return;
        }

        let atomic_state = self.atomic_state_for_virtual_context(&virtual_state.atomic_state);
        let mut ordered_indices = Self::order_atomic_indices(&atomic_items, &atomic_state);
        ordered_indices.extend(non_atomic_indices);
        if ordered_indices.len() == txs.len() {
            let mut ordered = ordered_indices.into_iter().map(|idx| txs[idx].clone()).collect();
            Self::sort_block_template_transactions_by_subnetwork(&mut ordered);
            *txs = ordered;
        }
    }

    fn sort_block_template_transactions_by_subnetwork(txs: &mut Vec<Transaction>) {
        txs.sort_by(|a, b| a.subnetwork_id.cmp(&b.subnetwork_id));
    }

    fn sort_block_template_transactions_and_fees_by_subnetwork(txs: &mut Vec<Transaction>, calculated_fees: &mut Vec<u64>) {
        debug_assert_eq!(txs.len(), calculated_fees.len());
        let mut ordered = txs.drain(..).zip(calculated_fees.drain(..)).collect_vec();
        ordered.sort_by(|(a, _), (b, _)| a.subnetwork_id.cmp(&b.subnetwork_id));
        for (tx, fee) in ordered {
            txs.push(tx);
            calculated_fees.push(fee);
        }
    }

    pub fn validate_mempool_transaction(&self, mutable_tx: &mut MutableTransaction, args: &TransactionValidationArgs) -> TxResult<()> {
        let virtual_read = self.virtual_stores.read();
        let virtual_state = virtual_read.state.get().unwrap();
        let virtual_utxo_view = &virtual_read.utxo_set;
        let virtual_daa_score = virtual_state.daa_score;
        let virtual_past_median_time = virtual_state.past_median_time;
        if !self.ensure_current_atomic_store_matches_virtual(&virtual_read, &virtual_state) {
            return Err(TxRuleError::InvalidAtomicPayload("Atomic state is not ready for mempool validation".to_string()));
        }
        self.validate_mempool_transaction_impl(
            mutable_tx,
            &virtual_state,
            virtual_utxo_view,
            virtual_daa_score,
            virtual_past_median_time,
            args,
        )
    }

    pub fn validate_mempool_transactions_in_parallel(
        &self,
        mutable_txs: &mut [MutableTransaction],
        args: &TransactionValidationBatchArgs,
    ) -> Vec<TxResult<()>> {
        let virtual_read = self.virtual_stores.read();
        let virtual_state = virtual_read.state.get().unwrap();
        let virtual_utxo_view = &virtual_read.utxo_set;
        let virtual_daa_score = virtual_state.daa_score;
        let virtual_past_median_time = virtual_state.past_median_time;
        if !self.ensure_current_atomic_store_matches_virtual(&virtual_read, &virtual_state) {
            return mutable_txs
                .iter()
                .map(|_| Err(TxRuleError::InvalidAtomicPayload("Atomic state is not ready for mempool validation".to_string())))
                .collect();
        }

        let mut results = self.thread_pool.install(|| {
            mutable_txs
                .par_iter_mut()
                .map(|mtx| {
                    self.validate_mempool_transaction_without_atomic(
                        mtx,
                        &virtual_utxo_view,
                        virtual_daa_score,
                        virtual_past_median_time,
                        args.get(&mtx.id()),
                    )
                })
                .collect::<Vec<TxResult<()>>>()
        });

        // Incoming P2P/RPC batches may contain the same transaction more than once, or
        // conflicting transactions racing on the same UTXO. Keep the batch deterministic
        // and avoid feeding duplicated candidates into the temporary Atomic state.
        let mut seen_batch_txids = HashSet::new();
        let mut seen_batch_spent_outpoints = HashSet::<TransactionOutpoint>::new();
        for (idx, mtx) in mutable_txs.iter().enumerate() {
            if results[idx].is_err() {
                continue;
            }
            let txid = mtx.id();
            if !seen_batch_txids.insert(txid) {
                warn!(
                    "Mempool batch rejected duplicate transaction before Atomic validation: txid={}, reason=duplicate_txid_in_validation_batch",
                    txid
                );
                results[idx] = Err(TxRuleError::InvalidAtomicPayload("duplicate transaction in mempool validation batch".to_string()));
                continue;
            }
            if let Some(conflicting_input) =
                mtx.tx.as_ref().inputs.iter().find(|input| seen_batch_spent_outpoints.contains(&input.previous_outpoint))
            {
                warn!(
                    "Mempool batch rejected UTXO-conflicting transaction before Atomic validation: txid={}, previous_outpoint={}, reason=input_already_spent_in_validation_batch",
                    txid, conflicting_input.previous_outpoint
                );
                results[idx] = Err(TxRuleError::MissingTxOutpoints);
                continue;
            }
            seen_batch_spent_outpoints.extend(mtx.tx.as_ref().inputs.iter().map(|input| input.previous_outpoint));
        }

        // Enforce CAT nonce/state transitions deterministically so results do not
        // depend on caller-provided slice order. Non-CAT transactions still pass
        // through the atomic-state validator so reserved liquidity vault scripts
        // are handled the same way as single validation and block templates.
        let mut ordered_atomic_items = Vec::new();
        let mut ordered_non_atomic_indices = Vec::new();
        for (idx, mtx) in mutable_txs.iter().enumerate() {
            if results[idx].is_err() {
                continue;
            }
            match self.extract_mempool_atomic_order_key(mtx, virtual_daa_score) {
                Ok(Some(info)) => ordered_atomic_items.push((idx, info)),
                Ok(None) => ordered_non_atomic_indices.push((mtx.id().as_bytes(), idx)),
                Err(err) => results[idx] = Err(err),
            }
        }
        let ordering_atomic_state = self.atomic_state_for_virtual_context(&virtual_state.atomic_state);
        let ordered_atomic_indices = Self::order_atomic_indices(&ordered_atomic_items, &ordering_atomic_state);
        ordered_non_atomic_indices.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

        let mut atomic_state = self.atomic_state_for_virtual_context(&virtual_state.atomic_state);
        let mut atomic_growth = AtomicBlockStateGrowth::default();
        let creation_context = AtomicCreationContext {
            source_block_hash: Hash::from_bytes([0u8; 32]),
            source_block_daa_score: virtual_daa_score,
            source_block_time: virtual_past_median_time,
        };
        for idx in ordered_atomic_indices.into_iter() {
            if results[idx].is_err() {
                continue;
            }
            let mtx = &mut mutable_txs[idx];
            if let Err(err) = self.validate_and_apply_atomic_state_transition_with_growth(
                &mtx.as_verifiable(),
                virtual_daa_score,
                creation_context,
                &mut atomic_state,
                &mut atomic_growth,
            ) {
                results[idx] = Err(err);
            }
        }
        for (_, idx) in ordered_non_atomic_indices.into_iter() {
            if results[idx].is_err() {
                continue;
            }
            let mtx = &mut mutable_txs[idx];
            if let Err(err) = self.validate_and_apply_atomic_state_transition_with_growth(
                &mtx.as_verifiable(),
                virtual_daa_score,
                creation_context,
                &mut atomic_state,
                &mut atomic_growth,
            ) {
                results[idx] = Err(err);
            }
        }
        results
    }

    fn populate_mempool_transaction_impl(
        &self,
        mutable_tx: &mut MutableTransaction,
        virtual_utxo_view: &impl UtxoView,
    ) -> TxResult<()> {
        self.populate_mempool_transaction_in_utxo_context(mutable_tx, virtual_utxo_view)?;
        Ok(())
    }

    pub fn populate_mempool_transaction(&self, mutable_tx: &mut MutableTransaction) -> TxResult<()> {
        let virtual_read = self.virtual_stores.read();
        let virtual_utxo_view = &virtual_read.utxo_set;
        self.populate_mempool_transaction_impl(mutable_tx, virtual_utxo_view)
    }

    pub fn populate_mempool_transactions_in_parallel(&self, mutable_txs: &mut [MutableTransaction]) -> Vec<TxResult<()>> {
        let virtual_read = self.virtual_stores.read();
        let virtual_utxo_view = &virtual_read.utxo_set;
        self.thread_pool.install(|| {
            mutable_txs
                .par_iter_mut()
                .map(|mtx| self.populate_mempool_transaction_impl(mtx, &virtual_utxo_view))
                .collect::<Vec<TxResult<()>>>()
        })
    }

    fn validate_block_template_transactions_in_parallel<V: UtxoView + Sync>(
        &self,
        txs: &[Transaction],
        virtual_state: &VirtualState,
        utxo_view: &V,
        atomic_state: &mut AtomicConsensusState,
        atomic_growth: &mut AtomicBlockStateGrowth,
    ) -> Vec<TxResult<u64>> {
        let mut txid_counts = HashMap::new();
        for tx in txs.iter() {
            *txid_counts.entry(tx.id()).or_insert(0usize) += 1;
        }
        let duplicate_txids = txid_counts.iter().filter_map(|(txid, count)| (*count > 1).then_some(*txid)).collect::<HashSet<_>>();
        let mut seen_txids = HashSet::new();
        let mut spent_outpoints = HashSet::<TransactionOutpoint>::new();
        let mut results = Vec::with_capacity(txs.len());
        for tx in txs.iter() {
            let txid = tx.id();
            if duplicate_txids.contains(&txid) {
                warn!(
                    "Block template rejected duplicate transaction before Atomic validation: txid={}, reason=duplicate_txid_in_template_candidate_set",
                    txid
                );
                results
                    .push(Err(TxRuleError::InvalidAtomicPayload("duplicate transaction in block template candidate set".to_string())));
                continue;
            }
            let validated = match self.validate_block_template_transaction(tx, virtual_state, utxo_view) {
                Ok(validated) => validated,
                Err(err) => {
                    results.push(Err(err));
                    continue;
                }
            };
            if !seen_txids.insert(txid) {
                warn!(
                    "Block template rejected duplicate transaction before Atomic validation: txid={}, reason=duplicate_txid_in_template_candidate_set",
                    txid
                );
                results
                    .push(Err(TxRuleError::InvalidAtomicPayload("duplicate transaction in block template candidate set".to_string())));
                continue;
            }
            if let Some(conflicting_input) = validated.inputs().iter().find(|input| spent_outpoints.contains(&input.previous_outpoint))
            {
                warn!(
                    "Block template rejected UTXO-conflicting transaction before Atomic validation: txid={}, previous_outpoint={}, reason=input_already_spent_in_template_candidate_set",
                    txid, conflicting_input.previous_outpoint
                );
                results.push(Err(TxRuleError::MissingTxOutpoints));
                continue;
            }
            let creation_context = AtomicCreationContext {
                source_block_hash: Hash::from_bytes([0u8; 32]),
                source_block_daa_score: virtual_state.daa_score,
                source_block_time: virtual_state.past_median_time,
            };
            match self.validate_and_apply_atomic_state_transition_with_growth(
                &validated,
                virtual_state.daa_score,
                creation_context,
                atomic_state,
                atomic_growth,
            ) {
                Ok(()) => {
                    spent_outpoints.extend(validated.inputs().iter().map(|input| input.previous_outpoint));
                    results.push(Ok(validated.calculated_fee));
                }
                Err(err) => results.push(Err(err)),
            }
        }
        results
    }

    fn validate_block_template_transaction<'a>(
        &self,
        tx: &'a Transaction,
        virtual_state: &VirtualState,
        utxo_view: &impl UtxoView,
    ) -> TxResult<ValidatedTransaction<'a>> {
        // No need to validate the transaction in isolation since we rely on the mining manager to submit transactions
        // which were previously validated through `validate_mempool_transaction_and_populate`, hence we only perform
        // in-context validations
        self.transaction_validator.utxo_free_tx_validation(tx, virtual_state.daa_score, virtual_state.past_median_time)?;
        self.validate_transaction_in_utxo_context(tx, utxo_view, virtual_state.daa_score, TxValidationFlags::Full)
    }

    pub fn build_block_template(
        &self,
        miner_data: MinerData,
        mut tx_selector: Box<dyn TemplateTransactionSelector>,
        build_mode: TemplateBuildMode,
    ) -> Result<BlockTemplate, RuleError> {
        //
        // TODO (relaxed): additional tests
        //

        // We call for the initial tx batch before acquiring the virtual read lock,
        // optimizing for the common case where all txs are valid. Following selection calls
        // are called within the lock in order to preserve validness of already validated txs
        self.repair_virtual_state_from_selected_chain_if_inconsistent("block template build");
        let mut txs = tx_selector.select_transactions();
        let mut calculated_fees = Vec::with_capacity(txs.len());
        let virtual_read = self.virtual_stores.read();
        let virtual_state = virtual_read.state.get().unwrap();
        let virtual_utxo_view = &virtual_read.utxo_set;
        self.ensure_virtual_parents_are_template_safe(&virtual_state)?;
        if !self.ensure_current_atomic_store_matches_virtual(&virtual_read, &virtual_state) {
            return Err(RuleError::KnownInvalid);
        }
        let mut template_atomic_state = self.atomic_state_for_virtual_context(&virtual_state.atomic_state);
        let mut template_atomic_growth = AtomicBlockStateGrowth::default();
        self.order_block_template_transactions(&mut txs, &virtual_state, virtual_utxo_view);

        let mut invalid_transactions = HashMap::new();
        let results = self.validate_block_template_transactions_in_parallel(
            &txs,
            &virtual_state,
            &virtual_utxo_view,
            &mut template_atomic_state,
            &mut template_atomic_growth,
        );
        for (tx, res) in txs.iter().zip(results) {
            match res {
                Err(e) => {
                    invalid_transactions.insert(tx.id(), e);
                    tx_selector.reject_selection(tx.id());
                }
                Ok(fee) => {
                    calculated_fees.push(fee);
                }
            }
        }

        let mut has_rejections = !invalid_transactions.is_empty();
        if has_rejections {
            txs.retain(|tx| !invalid_transactions.contains_key(&tx.id()));
        }

        while has_rejections {
            has_rejections = false;
            let mut next_batch = tx_selector.select_transactions(); // Note that once next_batch is empty the loop will exit
            self.order_block_template_transactions(&mut next_batch, &virtual_state, virtual_utxo_view);
            let next_batch_results = self.validate_block_template_transactions_in_parallel(
                &next_batch,
                &virtual_state,
                &virtual_utxo_view,
                &mut template_atomic_state,
                &mut template_atomic_growth,
            );
            for (tx, res) in next_batch.into_iter().zip(next_batch_results) {
                match res {
                    Err(e) => {
                        invalid_transactions.insert(tx.id(), e);
                        tx_selector.reject_selection(tx.id());
                        has_rejections = true;
                    }
                    Ok(fee) => {
                        txs.push(tx);
                        calculated_fees.push(fee);
                    }
                }
            }
        }

        // Check whether this was an overall successful selection episode. We pass this decision
        // to the selector implementation which has the broadest picture and can use mempool config
        // and context
        match (build_mode, tx_selector.is_successful()) {
            (TemplateBuildMode::Standard, false) => return Err(RuleError::InvalidTransactionsInNewBlock(invalid_transactions)),
            (TemplateBuildMode::Standard, true) | (TemplateBuildMode::Infallible, _) => {}
        }
        Self::sort_block_template_transactions_and_fees_by_subnetwork(&mut txs, &mut calculated_fees);

        // At this point we can safely drop the read lock
        drop(virtual_read);

        // Build the template
        self.build_block_template_from_virtual_state(virtual_state, miner_data, txs, calculated_fees)
    }

    pub(crate) fn validate_block_template_transactions(
        &self,
        txs: &[Transaction],
        virtual_state: &VirtualState,
        utxo_view: &impl UtxoView,
    ) -> Result<(), RuleError> {
        // Search for invalid transactions
        let mut invalid_transactions = HashMap::new();
        let mut atomic_state = self.atomic_state_for_virtual_context(&virtual_state.atomic_state);
        let mut atomic_growth = AtomicBlockStateGrowth::default();
        let mut seen_txids = HashSet::new();
        let mut spent_outpoints = HashSet::<TransactionOutpoint>::new();
        for tx in txs.iter() {
            match self.validate_block_template_transaction(tx, virtual_state, utxo_view) {
                Ok(validated) => {
                    let txid = validated.id();
                    if !seen_txids.insert(txid) {
                        invalid_transactions.insert(
                            txid,
                            TxRuleError::InvalidAtomicPayload("duplicate transaction in block template validation set".to_string()),
                        );
                        continue;
                    }
                    if validated.inputs().iter().any(|input| spent_outpoints.contains(&input.previous_outpoint)) {
                        invalid_transactions.insert(txid, TxRuleError::MissingTxOutpoints);
                        continue;
                    }
                    let creation_context = AtomicCreationContext {
                        source_block_hash: Hash::from_bytes([0u8; 32]),
                        source_block_daa_score: virtual_state.daa_score,
                        source_block_time: virtual_state.past_median_time,
                    };
                    if let Err(e) = self.validate_and_apply_atomic_state_transition_with_growth(
                        &validated,
                        virtual_state.daa_score,
                        creation_context,
                        &mut atomic_state,
                        &mut atomic_growth,
                    ) {
                        invalid_transactions.insert(tx.id(), e);
                    } else {
                        spent_outpoints.extend(validated.inputs().iter().map(|input| input.previous_outpoint));
                    }
                }
                Err(e) => {
                    invalid_transactions.insert(tx.id(), e);
                }
            }
        }
        if !invalid_transactions.is_empty() {
            Err(RuleError::InvalidTransactionsInNewBlock(invalid_transactions))
        } else {
            Ok(())
        }
    }

    pub(crate) fn build_block_template_from_virtual_state(
        &self,
        virtual_state: Arc<VirtualState>,
        miner_data: MinerData,
        mut txs: Vec<Transaction>,
        calculated_fees: Vec<u64>,
    ) -> Result<BlockTemplate, RuleError> {
        // [`calc_block_parents`] can use deep blocks below the pruning point for this calculation, so we
        // need to hold the pruning lock.
        let _prune_guard = self.pruning_lock.blocking_read();
        let pruning_info = self.pruning_point_store.read().get().unwrap();
        let header_pruning_point =
            self.pruning_point_manager.expected_header_pruning_point(virtual_state.ghostdag_data.to_compact(), pruning_info);
        let coinbase = self
            .coinbase_manager
            .expected_coinbase_transaction(
                virtual_state.daa_score,
                miner_data.clone(),
                &virtual_state.ghostdag_data,
                &virtual_state.mergeset_rewards,
                &virtual_state.mergeset_non_daa,
            )
            .unwrap();
        txs.insert(0, coinbase.tx);
        let version = BLOCK_VERSION;
        let parents_by_level = self.parents_manager.calc_block_parents(pruning_info.pruning_point, &virtual_state.parents);

        // Hash according to hardfork activation
        let storage_mass_activated = virtual_state.daa_score > self.storage_mass_activation_daa_score;
        let hash_merkle_root = calc_hash_merkle_root(txs.iter(), storage_mass_activated);

        let accepted_id_merkle_root = cryptix_merkle::calc_merkle_root(virtual_state.accepted_tx_ids.iter().copied());
        let utxo_commitment = virtual_state.multiset.clone().finalize();
        let state_commitment = virtual_state
            .atomic_state
            .header_commitment_for_state(utxo_commitment, self.transaction_validator.is_payload_hf_active(virtual_state.daa_score));
        // Past median time is the exclusive lower bound for valid block time, so we increase by 1 to get the valid min
        let min_block_time = virtual_state.past_median_time + 1;
        let header = Header::new_finalized(
            version,
            parents_by_level,
            hash_merkle_root,
            accepted_id_merkle_root,
            state_commitment,
            u64::max(min_block_time, unix_now()),
            virtual_state.bits,
            0,
            virtual_state.daa_score,
            virtual_state.ghostdag_data.blue_work,
            virtual_state.ghostdag_data.blue_score,
            header_pruning_point,
        );
        let selected_parent_hash = virtual_state.ghostdag_data.selected_parent;
        let selected_parent_timestamp = self.headers_store.get_timestamp(selected_parent_hash).unwrap();
        let selected_parent_daa_score = self.headers_store.get_daa_score(selected_parent_hash).unwrap();
        let virtual_state_approx_id = virtual_state.to_virtual_state_approx_id();
        Ok(BlockTemplate::new(
            MutableBlock::new(header, txs),
            miner_data,
            coinbase.has_red_reward,
            selected_parent_timestamp,
            selected_parent_daa_score,
            selected_parent_hash,
            virtual_state_approx_id,
            calculated_fees,
        ))
    }

    /// Make sure pruning point-related stores are initialized
    pub fn init(self: &Arc<Self>) {
        let pruning_point_read = self.pruning_point_store.upgradable_read();
        if pruning_point_read.pruning_point().unwrap_option().is_none() {
            let mut pruning_point_write = RwLockUpgradableReadGuard::upgrade(pruning_point_read);
            let mut pruning_utxoset_write = self.pruning_utxoset_stores.write();
            let mut batch = WriteBatch::default();
            self.past_pruning_points_store.insert_batch(&mut batch, 0, self.genesis.hash).unwrap_or_exists();
            pruning_point_write.set_batch(&mut batch, self.genesis.hash, self.genesis.hash, 0).unwrap();
            pruning_point_write.set_history_root(&mut batch, self.genesis.hash).unwrap();
            pruning_utxoset_write.set_utxoset_position(&mut batch, self.genesis.hash).unwrap();
            self.db.write(batch).unwrap();
            drop(pruning_point_write);
            drop(pruning_utxoset_write);
        }
        self.recover_pre_hf_virtual_atomic_state();
        self.repair_anchor_only_virtual_atomic_state_if_possible();
    }

    /// Initializes UTXO state of genesis and points virtual at genesis.
    /// Note that pruning point-related stores are initialized by `init`
    pub fn process_genesis(self: &Arc<Self>) {
        // Write the UTXO state of genesis
        self.commit_utxo_state(
            self.genesis.hash,
            UtxoDiff::default(),
            MuHash::new(),
            AcceptanceData::default(),
            AtomicConsensusState::default(),
        );

        // Init the virtual selected chain store
        let mut batch = WriteBatch::default();
        let mut selected_chain_write = self.selected_chain_store.write();
        selected_chain_write.init_with_pruning_point(&mut batch, self.genesis.hash).unwrap();
        self.db.write(batch).unwrap();
        drop(selected_chain_write);

        // Init virtual state
        self.commit_virtual_state(
            self.virtual_stores.upgradable_read(),
            Arc::new(VirtualState::from_genesis(&self.genesis, self.ghostdag_manager.ghostdag(&[self.genesis.hash]))),
            &Default::default(),
            &Default::default(),
        );
    }

    /// Finalizes the pruning point utxoset state and imports the pruning point utxoset *to* virtual utxoset
    pub fn import_pruning_point_utxo_set(
        &self,
        new_pruning_point: Hash,
        mut imported_utxo_multiset: MuHash,
    ) -> PruningImportResult<()> {
        info!("Importing the UTXO set of the pruning point {}", new_pruning_point);
        let new_pruning_point_header = self.headers_store.get_header(new_pruning_point).unwrap();
        let payload_hf_active = self.transaction_validator.is_payload_hf_active(new_pruning_point_header.daa_score);
        let imported_utxo_multiset_hash = imported_utxo_multiset.finalize();
        let pruning_point_atomic_state = if payload_hf_active {
            let root = self.atomic_state_store.get_root_record(new_pruning_point).map_err(|err| match err {
                StoreError::KeyNotFound(_) => PruningImportError::NewPruningPointMissingAtomicState(new_pruning_point),
                err => PruningImportError::AtomicStateStoreError(format!(
                    "failed reading pruning-point atomic root for `{new_pruning_point}`: {err}"
                )),
            })?;
            let imported_state_commitment =
                AtomicConsensusState::header_commitment(imported_utxo_multiset_hash, root.state_hash, true);
            if imported_state_commitment != new_pruning_point_header.utxo_commitment {
                return Err(PruningImportError::ImportedStateCommitmentMismatch(
                    new_pruning_point_header.utxo_commitment,
                    imported_state_commitment,
                ));
            }

            match self.atomic_state_store.read_current_root() {
                Ok(Some(current_root)) if AtomicConsensusState::root_only(current_root).canonical_hash() == root.state_hash => self
                    .atomic_state_store
                    .materialize_current_state(&AtomicConsensusState::root_only(current_root))
                    .map_err(|err| {
                        PruningImportError::AtomicStateStoreError(format!(
                            "failed materializing imported post-HF pruning-point Atomic state for `{new_pruning_point}`: {err}"
                        ))
                    })?,
                Ok(_) => {
                    let pruning_utxoset_read = self.pruning_utxoset_stores.read();
                    let reconstructed = Self::atomic_anchor_state_from_utxo_iterator(
                        pruning_utxoset_read.utxo_set.iterator(),
                        "post-HF pruning-point UTXO set",
                    )
                    .map_err(|err| {
                        PruningImportError::AtomicStateStoreError(format!(
                            "failed reconstructing post-HF pruning-point Atomic state from P2P UTXO set for `{new_pruning_point}`: {err}"
                        ))
                    })?;
                    drop(pruning_utxoset_read);

                    let reconstructed_hash = reconstructed.canonical_hash();
                    if reconstructed_hash != root.state_hash {
                        return Err(PruningImportError::AtomicStateStoreError(format!(
                            "post-HF pruning-point Atomic root cannot be reconstructed from P2P UTXO anchors alone for `{new_pruning_point}`; expected {}, rebuilt {}. A full Atomic state is required over the node sync protocol.",
                            faster_hex::hex_string(&root.state_hash),
                            faster_hex::hex_string(&reconstructed_hash)
                        )));
                    }

                    reconstructed
                }
                Err(err) => {
                    return Err(PruningImportError::AtomicStateStoreError(format!(
                        "failed reading imported post-HF pruning-point Atomic state root for `{new_pruning_point}`: {err}"
                    )))
                }
            }
        } else {
            self.reconstruct_pre_hf_pruning_point_atomic_state(new_pruning_point)?
        };
        let imported_state_commitment =
            pruning_point_atomic_state.header_commitment_for_state(imported_utxo_multiset_hash, payload_hf_active);
        if imported_state_commitment != new_pruning_point_header.utxo_commitment {
            return Err(PruningImportError::ImportedStateCommitmentMismatch(
                new_pruning_point_header.utxo_commitment,
                imported_state_commitment,
            ));
        }

        {
            // Set the pruning point utxoset position to the new point we just verified
            let mut batch = WriteBatch::default();
            let mut pruning_utxoset_write = self.pruning_utxoset_stores.write();
            pruning_utxoset_write.set_utxoset_position(&mut batch, new_pruning_point).unwrap();
            self.db.write(batch).unwrap();
            drop(pruning_utxoset_write);
        }

        {
            // Copy the pruning-point UTXO set into virtual's UTXO set
            let pruning_utxoset_read = self.pruning_utxoset_stores.read();
            let mut virtual_write = self.virtual_stores.write();

            virtual_write.utxo_set.clear().unwrap();
            for chunk in &pruning_utxoset_read.utxo_set.iterator().map(|iter_result| iter_result.unwrap()).chunks(1000) {
                virtual_write.utxo_set.write_from_iterator_without_cache(chunk).unwrap();
            }
        }

        let virtual_read = self.virtual_stores.upgradable_read();

        // Validate transactions of the pruning point itself
        let new_pruning_point_transactions = self.block_transactions_store.get(new_pruning_point).unwrap();
        let validated_transactions = self.validate_transactions_in_parallel(
            &new_pruning_point_transactions,
            &virtual_read.utxo_set,
            new_pruning_point_header.daa_score,
            TxValidationFlags::Full,
        );
        if validated_transactions.len() < new_pruning_point_transactions.len() - 1 {
            // Some non-coinbase transactions are invalid
            return Err(PruningImportError::NewPruningPointTxErrors);
        }

        if !payload_hf_active {
            let reconstructed_hash = pruning_point_atomic_state.canonical_hash();
            match self.atomic_state_store.get_root_record(new_pruning_point) {
                Ok(existing_root) if existing_root.state_hash == reconstructed_hash => {}
                Ok(_) => {
                    return Err(PruningImportError::AtomicStateStoreError(format!(
                        "existing pre-HF pruning-point atomic root for `{new_pruning_point}` differs from reconstructed root"
                    )));
                }
                Err(StoreError::KeyNotFound(_)) => {
                    let mut batch = WriteBatch::default();
                    self.atomic_state_store.insert_root_batch(&mut batch, new_pruning_point, reconstructed_hash).map_err(|err| {
                        PruningImportError::AtomicStateStoreError(format!(
                            "failed writing reconstructed pruning-point atomic root for `{new_pruning_point}`: {err}"
                        ))
                    })?;
                    self.db.write(batch).map_err(|err| {
                        PruningImportError::AtomicStateStoreError(format!(
                            "failed committing reconstructed pruning-point atomic root for `{new_pruning_point}`: {err}"
                        ))
                    })?;
                }
                Err(err) => {
                    return Err(PruningImportError::AtomicStateStoreError(format!(
                        "failed reading pruning-point atomic root for `{new_pruning_point}`: {err}"
                    )));
                }
            }
        }

        {
            // Submit partial UTXO state for the pruning point.
            // Note we only have and need the multiset; acceptance data and utxo-diff are irrelevant.
            let mut batch = WriteBatch::default();
            self.utxo_multisets_store.set_batch(&mut batch, new_pruning_point, imported_utxo_multiset.clone()).unwrap();

            let statuses_write = self.statuses_store.set_batch(&mut batch, new_pruning_point, StatusUTXOValid).unwrap();
            self.db.write(batch).unwrap();
            drop(statuses_write);
        }

        // Calculate the virtual state, treating the pruning point as the only virtual parent
        let virtual_parents = vec![new_pruning_point];
        let virtual_ghostdag_data = self.ghostdag_manager.ghostdag(&virtual_parents);

        self.calculate_and_commit_virtual_state(
            virtual_read,
            virtual_parents,
            virtual_ghostdag_data,
            imported_utxo_multiset.clone(),
            &mut UtxoDiff::default(),
            pruning_point_atomic_state,
            &ChainPath::default(),
        )?;

        Ok(())
    }

    fn recover_pre_hf_virtual_atomic_state(&self) {
        let virtual_read = self.virtual_stores.upgradable_read();
        let Ok(virtual_state) = virtual_read.state.get() else {
            return;
        };
        if self.transaction_validator.is_payload_hf_active(virtual_state.daa_score) {
            return;
        }

        let reconstructed = match Self::atomic_anchor_state_from_utxo_iterator(virtual_read.utxo_set.iterator(), "virtual UTXO set") {
            Ok(state) => state,
            Err(err) => {
                warn!("failed reconstructing pre-HF virtual atomic consensus state: {err}");
                return;
            }
        };
        let reconstructed_root = reconstructed.root_accumulator();
        let virtual_matches = reconstructed.canonical_hash() == virtual_state.atomic_state.canonical_hash();
        let current_matches = match self.atomic_state_store.read_current_root() {
            Ok(Some(current_root)) => current_root == reconstructed_root,
            Ok(None) => false,
            Err(err) => {
                warn!("failed reading pre-HF Atomic V2 current root; repairing from current UTXO set: {err}");
                false
            }
        };
        if virtual_matches && current_matches {
            return;
        }

        warn!("reconstructing pre-HF virtual atomic consensus state from the current UTXO set");
        let mut updated_virtual_state = virtual_state.as_ref().clone();
        updated_virtual_state.atomic_state = reconstructed.as_virtual_root_state();

        let mut batch = WriteBatch::default();
        let mut virtual_write = RwLockUpgradableReadGuard::upgrade(virtual_read);
        self.atomic_state_store.write_current_overlay_batch(&mut batch, &reconstructed).unwrap();
        virtual_write.state.set_batch(&mut batch, Arc::new(updated_virtual_state)).unwrap();
        self.db.write(batch).unwrap();
    }

    fn repair_anchor_only_virtual_atomic_state_if_possible(&self) {
        let virtual_read = self.virtual_stores.upgradable_read();
        let Ok(virtual_state) = virtual_read.state.get() else {
            return;
        };
        let expected_root = virtual_state.atomic_state.root_accumulator();
        let current_root = match self.atomic_state_store.read_current_root() {
            Ok(root) => root,
            Err(err) => {
                warn!("failed reading Atomic V2 current root while checking anchor-only repair: {err}");
                None
            }
        };
        if current_root == Some(expected_root) || current_root.is_none() && expected_root == Default::default() {
            return;
        }

        let rebuilt = match Self::atomic_anchor_state_from_utxo_iterator(virtual_read.utxo_set.iterator(), "virtual UTXO set") {
            Ok(state) => state,
            Err(err) => {
                warn!("failed reconstructing anchor-only Atomic V2 state from virtual UTXO set: {err}");
                return;
            }
        };
        let rebuilt_root = rebuilt.root_accumulator();

        match self.selected_chain_has_atomic_payload_transactions() {
            Ok(false) => {}
            Ok(true) => {
                warn!(
                    "Atomic V2 anchor-only repair refused: selected chain contains Atomic payload transactions; snapshot or selected-chain deltas are required"
                );
                return;
            }
            Err(err) => {
                warn!("Atomic V2 anchor-only repair refused: failed scanning selected chain for Atomic payload transactions: {err}");
                return;
            }
        }

        warn!(
            "repairing Atomic V2 virtual/current state from anchor-only UTXO reconstruction: virtual={}, current={}, rebuilt={}",
            faster_hex::hex_string(&AtomicConsensusState::root_only(expected_root).canonical_hash()),
            current_root
                .map(|root| faster_hex::hex_string(&AtomicConsensusState::root_only(root).canonical_hash()))
                .unwrap_or_else(|| "missing".to_string()),
            faster_hex::hex_string(&AtomicConsensusState::root_only(rebuilt_root).canonical_hash())
        );

        let mut updated_virtual_state = virtual_state.as_ref().clone();
        updated_virtual_state.atomic_state = rebuilt.as_virtual_root_state();

        let mut batch = WriteBatch::default();
        let mut virtual_write = RwLockUpgradableReadGuard::upgrade(virtual_read);
        self.atomic_state_store
            .replace_current_overlay_batch(&mut batch, &rebuilt)
            .expect("anchor-only Atomic V2 current-state repair should write");
        virtual_write.state.set_batch(&mut batch, Arc::new(updated_virtual_state)).unwrap();
        self.db.write(batch).unwrap();
    }

    fn selected_chain_has_atomic_payload_transactions(&self) -> Result<bool, String> {
        let (tip_index, _) =
            self.selected_chain_store.read().get_tip().map_err(|err| format!("selected chain tip unavailable: {err}"))?;
        let selected_chain_read = self.selected_chain_store.read();
        for index in 1..=tip_index {
            let block_hash =
                selected_chain_read.get_by_index(index).map_err(|err| format!("selected-chain index `{index}` unavailable: {err}"))?;
            let txs = self
                .block_transactions_store
                .get(block_hash)
                .map_err(|err| format!("selected-chain block `{block_hash}` transactions unavailable: {err}"))?;
            for tx in txs.iter().skip(1) {
                if !tx.subnetwork_id.is_payload() || tx.payload.is_empty() {
                    continue;
                }
                match parse_atomic_payload(tx.payload.as_slice()) {
                    Ok(None) => {}
                    Ok(Some(_)) | Err(_) => return Ok(true),
                }
            }
        }
        Ok(false)
    }

    fn rebuild_current_atomic_store_from_selected_chain(&self, virtual_state: &VirtualState) -> Result<(), String> {
        let expected_root = virtual_state.atomic_state.root_accumulator();
        let (tip_index, tip_hash) =
            self.selected_chain_store.read().get_tip().map_err(|err| format!("selected chain tip unavailable: {err}"))?;
        let selected_parent = virtual_state.ghostdag_data.selected_parent;
        if tip_hash != selected_parent {
            return Err(format!("selected-chain tip `{tip_hash}` does not match virtual selected parent `{selected_parent}`"));
        }

        let mut rebuilt = AtomicConsensusState::default();
        let mut replayed_blocks = 0u64;
        {
            let selected_chain_read = self.selected_chain_store.read();
            for index in 1..=tip_index {
                let block_hash = selected_chain_read
                    .get_by_index(index)
                    .map_err(|err| format!("selected-chain index `{index}` unavailable: {err}"))?;
                let delta = match self.atomic_state_store.get_delta(block_hash) {
                    Ok(delta) => delta,
                    Err(err) => {
                        warn!(
                            "Atomic V2 selected-chain delta replay is incomplete at block `{block_hash}` ({err}); rebuilding from local block data"
                        );
                        return self.rebuild_current_atomic_store_from_selected_chain_blocks(virtual_state, tip_index, tip_hash);
                    }
                };
                rebuilt
                    .apply_delta_forward(delta.as_ref())
                    .map_err(|err| format!("failed replaying Atomic delta for selected-chain block `{block_hash}`: {err}"))?;
                replayed_blocks += 1;
            }
        }

        rebuilt
            .apply_delta_forward(&virtual_state.atomic_diff)
            .map_err(|err| format!("failed replaying virtual Atomic delta: {err}"))?;

        let rebuilt_root = rebuilt.root_accumulator();
        if rebuilt_root != expected_root {
            warn!(
                "Atomic V2 selected-chain delta replay root mismatch; rebuilding from local block data: virtual={}, rebuilt={} (selected blocks replayed: {}, tip: `{tip_hash}`)",
                faster_hex::hex_string(&AtomicConsensusState::root_only(expected_root).canonical_hash()),
                faster_hex::hex_string(&AtomicConsensusState::root_only(rebuilt_root).canonical_hash()),
                replayed_blocks
            );
            return self.rebuild_current_atomic_store_from_selected_chain_blocks(virtual_state, tip_index, tip_hash);
        }

        let mut batch = WriteBatch::default();
        self.atomic_state_store
            .replace_current_overlay_batch(&mut batch, &rebuilt)
            .map_err(|err| format!("failed writing rebuilt Atomic V2 current-state KV store: {err}"))?;
        self.db.write(batch).map_err(|err| format!("failed committing rebuilt Atomic V2 current-state KV store: {err}"))?;
        info!(
            "rebuilt Atomic V2 current-state KV store from {} selected-chain block delta(s), root={}",
            replayed_blocks,
            faster_hex::hex_string(&AtomicConsensusState::root_only(expected_root).canonical_hash())
        );
        Ok(())
    }

    fn rebuild_current_atomic_store_from_selected_chain_blocks(
        &self,
        virtual_state: &VirtualState,
        tip_index: u64,
        tip_hash: Hash,
    ) -> Result<(), String> {
        let expected_root = virtual_state.atomic_state.root_accumulator();
        let mut rebuilt = AtomicConsensusState::default();
        let mut batch = WriteBatch::default();
        let mut replayed_blocks = 0u64;
        let mut replayed_transactions = 0u64;

        {
            let selected_chain_read = self.selected_chain_store.read();
            let base_hash =
                selected_chain_read.get_by_index(0).map_err(|err| format!("selected-chain base block unavailable: {err}"))?;
            if base_hash != self.genesis.hash {
                let base_hash_record = self.atomic_state_store.get_root_record(base_hash).map_err(|err| {
                    format!(
                        "selected-chain local block replay starts at non-genesis pruning point `{base_hash}` and has no usable Atomic snapshot: {err}"
                    )
                })?;
                let empty_hash = AtomicConsensusState::default().canonical_hash();
                if base_hash_record.state_hash != empty_hash {
                    return Err(format!(
                        "selected-chain local block replay starts at post-Atomic pruning point `{base_hash}`; import an Atomic V2 snapshot before replaying above it"
                    ));
                }
            }

            for index in 1..=tip_index {
                let block_hash = selected_chain_read
                    .get_by_index(index)
                    .map_err(|err| format!("selected-chain index `{index}` unavailable: {err}"))?;
                let pov_daa_score = self
                    .headers_store
                    .get_header(block_hash)
                    .map_err(|err| format!("selected-chain block `{block_hash}` header unavailable: {err}"))?
                    .daa_score;

                rebuilt.begin_delta_tracking();
                let accepted = self.replay_atomic_acceptance_for_block(block_hash, pov_daa_score, &mut rebuilt)?;
                let delta = Arc::new(rebuilt.take_delta());
                let state_hash = rebuilt.canonical_hash();
                self.atomic_state_store
                    .repair_batch_with_delta(&mut batch, block_hash, state_hash, delta)
                    .map_err(|err| format!("failed writing repaired Atomic delta for selected-chain block `{block_hash}`: {err}"))?;

                replayed_blocks += 1;
                replayed_transactions += accepted;
                if replayed_blocks % 5_000 == 0 {
                    info!(
                        "Atomic V2 local selected-chain replay progress: {}/{} block(s), {} accepted non-coinbase tx(s)",
                        replayed_blocks, tip_index, replayed_transactions
                    );
                }
            }
        }

        rebuilt
            .apply_delta_forward(&virtual_state.atomic_diff)
            .map_err(|err| format!("failed replaying virtual Atomic delta after local block replay: {err}"))?;

        let rebuilt_root = rebuilt.root_accumulator();
        if rebuilt_root != expected_root {
            return Err(format!(
                "local selected-chain block replay root mismatch: virtual={}, rebuilt={} (selected blocks replayed: {}, accepted non-coinbase txs replayed: {}, tip: `{tip_hash}`)",
                faster_hex::hex_string(&AtomicConsensusState::root_only(expected_root).canonical_hash()),
                faster_hex::hex_string(&AtomicConsensusState::root_only(rebuilt_root).canonical_hash()),
                replayed_blocks,
                replayed_transactions
            ));
        }

        self.atomic_state_store
            .replace_current_overlay_batch(&mut batch, &rebuilt)
            .map_err(|err| format!("failed writing locally replayed Atomic V2 current-state KV store: {err}"))?;
        self.db.write(batch).map_err(|err| format!("failed committing locally replayed Atomic V2 current-state KV store: {err}"))?;
        info!(
            "rebuilt Atomic V2 current-state KV store and repaired block deltas from local selected-chain block data: {} block(s), {} accepted non-coinbase tx(s), root={}",
            replayed_blocks,
            replayed_transactions,
            faster_hex::hex_string(&AtomicConsensusState::root_only(expected_root).canonical_hash())
        );
        Ok(())
    }

    fn replay_atomic_acceptance_for_block(
        &self,
        block_hash: Hash,
        pov_daa_score: u64,
        atomic_state: &mut AtomicConsensusState,
    ) -> Result<u64, String> {
        let acceptance_data = self
            .acceptance_data_store
            .get(block_hash)
            .map_err(|err| format!("block `{block_hash}` acceptance data unavailable: {err}"))?;
        let utxo_diff =
            self.utxo_diffs_store.get(block_hash).map_err(|err| format!("block `{block_hash}` UTXO diff unavailable: {err}"))?;
        let mut growth = AtomicBlockStateGrowth::default();
        let mut replayed_transactions = 0u64;

        for accepted_block in acceptance_data.iter() {
            let source_header = self.headers_store.get_header(accepted_block.block_hash).map_err(|err| {
                format!("accepted block `{}` header unavailable while replaying `{block_hash}`: {err}", accepted_block.block_hash)
            })?;
            let creation_context = AtomicCreationContext {
                source_block_hash: accepted_block.block_hash,
                source_block_daa_score: source_header.daa_score,
                source_block_time: source_header.timestamp,
            };
            let txs = self.block_transactions_store.get(accepted_block.block_hash).map_err(|err| {
                format!(
                    "accepted block `{}` transaction list unavailable while replaying `{block_hash}`: {err}",
                    accepted_block.block_hash
                )
            })?;

            for accepted_tx in accepted_block.accepted_transactions.iter() {
                let tx = txs.get(accepted_tx.index_within_block as usize).ok_or_else(|| {
                    format!(
                        "accepted tx index `{}` is out of bounds for block `{}` while replaying `{block_hash}`",
                        accepted_tx.index_within_block, accepted_block.block_hash
                    )
                })?;
                if tx.id() != accepted_tx.transaction_id {
                    return Err(format!(
                        "accepted tx id mismatch for block `{}` index `{}` while replaying `{block_hash}`: acceptance={}, actual={}",
                        accepted_block.block_hash,
                        accepted_tx.index_within_block,
                        accepted_tx.transaction_id,
                        tx.id()
                    ));
                }
                if tx.is_coinbase() {
                    continue;
                }

                let mut entries = Vec::with_capacity(tx.inputs.len());
                for input in tx.inputs.iter() {
                    let entry = utxo_diff.removed().get(&input.previous_outpoint).ok_or_else(|| {
                        format!(
                            "accepted tx `{}` input `{}` has no removed UTXO entry in block `{block_hash}` diff",
                            tx.id(),
                            input.previous_outpoint
                        )
                    })?;
                    entries.push(entry.clone());
                }
                let populated = PopulatedTransaction::new(tx, entries);
                self.validate_and_apply_atomic_state_transition_with_growth(
                    &populated,
                    pov_daa_score,
                    creation_context,
                    atomic_state,
                    &mut growth,
                )
                .map_err(|err| {
                    format!(
                        "failed replaying Atomic transition for accepted tx `{}` in block `{}` while rebuilding `{block_hash}`: {err}",
                        tx.id(),
                        accepted_block.block_hash
                    )
                })?;
                replayed_transactions += 1;
            }
        }

        Ok(replayed_transactions)
    }

    fn rebuild_current_atomic_store_from_virtual_utxo(
        &self,
        virtual_stores: &VirtualStores,
        virtual_state: &VirtualState,
    ) -> Result<(), String> {
        let expected_root = virtual_state.atomic_state.root_accumulator();
        let rebuilt = Self::atomic_anchor_state_from_utxo_iterator(virtual_stores.utxo_set.iterator(), "virtual UTXO set")?;
        let rebuilt_root = rebuilt.root_accumulator();
        if rebuilt_root == expected_root {
            self.replace_current_atomic_store(&rebuilt, "virtual UTXO set", expected_root)?;
            return Ok(());
        }

        let legacy_rebuilt = Self::atomic_anchor_state_from_utxo_iterator_with_coinbase(
            virtual_stores.utxo_set.iterator(),
            "virtual UTXO set (legacy coinbase-inclusive)",
        )?;
        let legacy_rebuilt_root = legacy_rebuilt.root_accumulator();
        if legacy_rebuilt_root == expected_root {
            self.replace_current_atomic_store(
                &legacy_rebuilt,
                "virtual UTXO set using legacy coinbase-inclusive anchor reconstruction",
                expected_root,
            )?;
            return Ok(());
        }

        Err(format!(
            "virtual UTXO reconstruction root mismatch: virtual={}, rebuilt={}, legacy_coinbase_inclusive={} (this node needs selected-chain Atomic deltas or a compatible snapshot)",
            faster_hex::hex_string(&AtomicConsensusState::root_only(expected_root).canonical_hash()),
            faster_hex::hex_string(&AtomicConsensusState::root_only(rebuilt_root).canonical_hash()),
            faster_hex::hex_string(&AtomicConsensusState::root_only(legacy_rebuilt_root).canonical_hash())
        ))
    }

    fn replace_current_atomic_store(
        &self,
        state: &AtomicConsensusState,
        source_label: &str,
        expected_root: AtomicConsensusRootAccumulator,
    ) -> Result<(), String> {
        let mut batch = WriteBatch::default();
        self.atomic_state_store
            .replace_current_overlay_batch(&mut batch, state)
            .map_err(|err| format!("failed writing UTXO-rebuilt Atomic V2 current-state KV store: {err}"))?;
        self.db.write(batch).map_err(|err| format!("failed committing UTXO-rebuilt Atomic V2 current-state KV store: {err}"))?;
        info!(
            "rebuilt Atomic V2 current-state KV store from {}, root={}",
            source_label,
            faster_hex::hex_string(&AtomicConsensusState::root_only(expected_root).canonical_hash())
        );
        Ok(())
    }

    fn reconstruct_pre_hf_pruning_point_atomic_state(&self, new_pruning_point: Hash) -> PruningImportResult<AtomicConsensusState> {
        let pruning_utxoset_read = self.pruning_utxoset_stores.read();
        Self::atomic_anchor_state_from_utxo_iterator(pruning_utxoset_read.utxo_set.iterator(), "pruning-point UTXO set").map_err(
            |err| {
                PruningImportError::AtomicStateStoreError(format!(
                    "failed reconstructing pre-HF pruning-point atomic state for `{new_pruning_point}`: {err}"
                ))
            },
        )
    }

    pub(super) fn atomic_anchor_state_from_utxo_iterator<E>(
        utxos: impl IntoIterator<Item = Result<(TransactionOutpoint, Arc<UtxoEntry>), E>>,
        context: &str,
    ) -> Result<AtomicConsensusState, String>
    where
        E: std::fmt::Display,
    {
        Self::atomic_anchor_state_from_utxo_iterator_inner(utxos, context, false)
    }

    fn atomic_anchor_state_from_utxo_iterator_with_coinbase<E>(
        utxos: impl IntoIterator<Item = Result<(TransactionOutpoint, Arc<UtxoEntry>), E>>,
        context: &str,
    ) -> Result<AtomicConsensusState, String>
    where
        E: std::fmt::Display,
    {
        Self::atomic_anchor_state_from_utxo_iterator_inner(utxos, context, true)
    }

    fn atomic_anchor_state_from_utxo_iterator_inner<E>(
        utxos: impl IntoIterator<Item = Result<(TransactionOutpoint, Arc<UtxoEntry>), E>>,
        context: &str,
        include_coinbase: bool,
    ) -> Result<AtomicConsensusState, String>
    where
        E: std::fmt::Display,
    {
        let mut state = AtomicConsensusState::default();
        for item in utxos {
            let (_outpoint, entry) = item.map_err(|err| format!("failed iterating {context}: {err}"))?;
            Self::add_atomic_anchor_count_with_policy(&mut state, &entry, include_coinbase)?;
        }
        state.validate_normalized()?;
        Ok(state)
    }

    fn add_atomic_anchor_count(state: &mut AtomicConsensusState, entry: &UtxoEntry) -> Result<(), String> {
        Self::add_atomic_anchor_count_with_policy(state, entry, false)
    }

    fn add_atomic_anchor_count_with_policy(
        state: &mut AtomicConsensusState,
        entry: &UtxoEntry,
        include_coinbase: bool,
    ) -> Result<(), String> {
        if entry.is_coinbase && !include_coinbase {
            return Ok(());
        }
        let Some(owner_id) = atomic_owner_id_from_script(&entry.script_public_key) else {
            return Ok(());
        };
        let count = state
            .anchor_count(&owner_id)
            .checked_add(1)
            .ok_or_else(|| format!("atomic anchor count overflow for owner `{}`", faster_hex::hex_string(&owner_id)))?;
        state.set_anchor_count(owner_id, count);
        Ok(())
    }

    fn remove_atomic_anchor_count(state: &mut AtomicConsensusState, entry: &UtxoEntry) -> Result<(), String> {
        if entry.is_coinbase {
            return Ok(());
        }
        let Some(owner_id) = atomic_owner_id_from_script(&entry.script_public_key) else {
            return Ok(());
        };
        let count = state
            .anchor_count(&owner_id)
            .checked_sub(1)
            .ok_or_else(|| format!("atomic anchor count underflow for owner `{}`", faster_hex::hex_string(&owner_id)))?;
        state.set_anchor_count(owner_id, count);
        Ok(())
    }

    fn pre_hf_atomic_state_from_virtual_diff(
        &self,
        stores: &VirtualStores,
        diff_from_virtual: &impl ImmutableUtxoDiff,
        block_hash: Hash,
    ) -> Option<AtomicConsensusState> {
        let block_daa_score = self.headers_store.get_header(block_hash).unwrap().daa_score;
        if self.transaction_validator.is_payload_hf_active(block_daa_score) {
            warn!("refusing to reconstruct post-HF atomic state for `{block_hash}` from the virtual UTXO set");
            return None;
        }

        let mut state = match Self::atomic_anchor_state_from_utxo_iterator(stores.utxo_set.iterator(), "virtual UTXO set") {
            Ok(state) => state,
            Err(err) => {
                warn!("failed reconstructing pre-HF atomic state for `{block_hash}` from virtual UTXO set: {err}");
                return None;
            }
        };

        for entry in diff_from_virtual.removed().values() {
            if let Err(err) = Self::remove_atomic_anchor_count(&mut state, entry) {
                warn!("failed applying removed UTXO anchor while reconstructing pre-HF atomic state for `{block_hash}`: {err}");
                return None;
            }
        }
        for entry in diff_from_virtual.added().values() {
            if let Err(err) = Self::add_atomic_anchor_count(&mut state, entry) {
                warn!("failed applying added UTXO anchor while reconstructing pre-HF atomic state for `{block_hash}`: {err}");
                return None;
            }
        }
        if let Err(err) = state.validate_normalized() {
            warn!("reconstructed pre-HF atomic state for `{block_hash}` is not normalized: {err}");
            return None;
        }
        Some(state)
    }

    pub fn import_pruning_point_atomic_state(
        &self,
        new_pruning_point: Hash,
        imported_atomic_state: PruningPointAtomicState,
    ) -> PruningImportResult<()> {
        let expected_hash = imported_atomic_state.state_hash;
        let full_state = match imported_atomic_state.state_bytes.as_deref() {
            Some(bytes) => {
                let actual_hash = AtomicConsensusState::canonical_hash_from_canonical_bytes(bytes).map_err(|err| {
                    PruningImportError::AtomicStateStoreError(format!(
                        "invalid pruning-point Atomic state bytes for `{new_pruning_point}`: {err}"
                    ))
                })?;
                if actual_hash != expected_hash {
                    return Err(PruningImportError::AtomicStateStoreError(format!(
                        "full pruning-point Atomic state root mismatch for `{new_pruning_point}`: expected {}, got {}",
                        faster_hex::hex_string(&expected_hash),
                        faster_hex::hex_string(&actual_hash)
                    )));
                }
                AtomicConsensusState::try_from_canonical_bytes(bytes).ok()
            }
            None => None,
        };
        match self.atomic_state_store.get_root_record(new_pruning_point) {
            Ok(existing_root) => {
                if existing_root.state_hash != expected_hash {
                    return Err(PruningImportError::AtomicStateStoreError(format!(
                        "existing pruning-point atomic root for `{new_pruning_point}` differs from imported root"
                    )));
                }
            }
            Err(StoreError::KeyNotFound(_)) => {
                let mut batch = WriteBatch::default();
                self.atomic_state_store.insert_root_batch(&mut batch, new_pruning_point, expected_hash).map_err(|err| {
                    PruningImportError::AtomicStateStoreError(format!(
                        "failed writing pruning-point atomic root for `{new_pruning_point}`: {err}"
                    ))
                })?;
                self.db.write(batch).map_err(|err| {
                    PruningImportError::AtomicStateStoreError(format!(
                        "failed committing pruning-point atomic root for `{new_pruning_point}`: {err}"
                    ))
                })?;
            }
            Err(err) => {
                return Err(PruningImportError::AtomicStateStoreError(format!(
                    "failed reading pruning-point atomic root for `{new_pruning_point}`: {err}"
                )))
            }
        }

        if let Some(full_state) = full_state {
            let mut batch = WriteBatch::default();
            self.atomic_state_store.replace_current_overlay_batch(&mut batch, &full_state).map_err(|err| {
                PruningImportError::AtomicStateStoreError(format!(
                    "failed writing full pruning-point Atomic state for `{new_pruning_point}`: {err}"
                ))
            })?;
            self.db.write(batch).map_err(|err| {
                PruningImportError::AtomicStateStoreError(format!(
                    "failed committing full pruning-point Atomic state for `{new_pruning_point}`: {err}"
                ))
            })?;
        }
        Ok(())
    }

    pub fn get_atomic_state_hash(&self, block_hash: Hash) -> ConsensusResult<Option<[u8; 32]>> {
        match self.atomic_state_store.get_root_record(block_hash) {
            Ok(root) => Ok(Some(root.state_hash)),
            Err(StoreError::KeyNotFound(_)) => Ok(None),
            Err(_) => Err(ConsensusError::General("failed reading atomic consensus root")),
        }
    }

    pub fn get_atomic_p2p_token_audit_hash(&self, block_hash: Hash) -> ConsensusResult<Option<[u8; 32]>> {
        let expected_state_hash = match self.atomic_state_store.get_root_record(block_hash) {
            Ok(root) => root.state_hash,
            Err(StoreError::KeyNotFound(_)) => return Ok(None),
            Err(_) => return Err(ConsensusError::General("failed reading atomic consensus root")),
        };

        match self.materialize_selected_chain_atomic_state_at(block_hash, expected_state_hash) {
            Ok(Some(state)) => Ok(state.p2p_token_audit_hash()),
            Ok(None) => Ok(None),
            Err(err) => {
                warn!("failed materializing Atomic P2P token audit state for `{block_hash}`: {err}");
                Err(ConsensusError::General("failed materializing atomic p2p token audit state"))
            }
        }
    }

    fn materialize_selected_chain_atomic_state_at(
        &self,
        target_hash: Hash,
        expected_state_hash: [u8; 32],
    ) -> Result<Option<AtomicConsensusState>, String> {
        let virtual_state = self.virtual_stores.read().state.get().map_err(|err| format!("virtual state unavailable: {err}"))?;
        let mut state = self
            .atomic_state_store
            .materialize_current_state(&virtual_state.atomic_state)
            .map_err(|err| format!("current Atomic state unavailable: {err}"))?;
        state
            .apply_delta_rollback(&virtual_state.atomic_diff)
            .map_err(|err| format!("failed rolling back virtual Atomic diff: {err}"))?;

        let selected_chain_read = self.selected_chain_store.read();
        let (tip_index, _) = selected_chain_read.get_tip().map_err(|err| format!("selected-chain tip unavailable: {err}"))?;
        let target_index = match selected_chain_read.get_by_hash(target_hash) {
            Ok(index) => index,
            Err(StoreError::KeyNotFound(_)) => return Ok(None),
            Err(err) => return Err(format!("selected-chain hash `{target_hash}` unavailable: {err}")),
        };
        if target_index > tip_index {
            return Ok(None);
        }

        for index in ((target_index + 1)..=tip_index).rev() {
            let block_hash =
                selected_chain_read.get_by_index(index).map_err(|err| format!("selected-chain index `{index}` unavailable: {err}"))?;
            let delta = self
                .atomic_state_store
                .get_delta(block_hash)
                .map_err(|err| format!("Atomic delta for selected-chain block `{block_hash}` unavailable: {err}"))?;
            state
                .apply_delta_rollback(delta.as_ref())
                .map_err(|err| format!("failed rolling back Atomic delta for selected-chain block `{block_hash}`: {err}"))?;
        }
        drop(selected_chain_read);

        let actual_state_hash = state.canonical_hash();
        if actual_state_hash != expected_state_hash {
            return Err(format!(
                "materialized Atomic root mismatch for `{target_hash}`: expected {}, got {}",
                faster_hex::hex_string(&expected_state_hash),
                faster_hex::hex_string(&actual_state_hash)
            ));
        }

        Ok(Some(state))
    }

    pub fn are_pruning_points_violating_finality(&self, pp_list: PruningPointsList) -> bool {
        // Ideally we would want to check if the last known pruning point has the finality point
        // in its chain, but in some cases it's impossible: let `lkp` be the last known pruning
        // point from the list, and `fup` be the first unknown pruning point (the one following `lkp`).
        // fup.blue_score - lkp.blue_score ≈ finality_depth (±k), so it's possible for `lkp` not to
        // have the finality point in its past. So we have no choice but to check if `lkp`
        // has `finality_point.finality_point` in its chain (in the worst case `fup` is one block
        // above the current finality point, and in this case `lkp` will be a few blocks above the
        // finality_point.finality_point), meaning this function can only detect finality violations
        // in depth of 2*finality_depth, and can give false negatives for smaller finality violations.
        let current_pp = self.pruning_point_store.read().pruning_point().unwrap();
        let vf = self.virtual_finality_point(&self.lkg_virtual_state.load().ghostdag_data, current_pp);
        let vff = self.depth_manager.calc_finality_point(&self.ghostdag_primary_store.get_data(vf).unwrap(), current_pp);

        let last_known_pp = pp_list.iter().rev().find(|pp| match self.statuses_store.read().get(pp.hash).unwrap_option() {
            Some(status) => status.is_valid(),
            None => false,
        });

        if let Some(last_known_pp) = last_known_pp {
            !self.reachability_service.is_chain_ancestor_of(vff, last_known_pp.hash)
        } else {
            // If no pruning point is known, there's definitely a finality violation
            // (normally at least genesis should be known).
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptix_consensus_core::{
        constants::{MAX_TX_IN_SEQUENCE_NUM, TX_VERSION},
        subnets::{SubnetworkId, SUBNETWORK_ID_NATIVE, SUBNETWORK_ID_PAYLOAD},
        tx::{ScriptPublicKey, ScriptVec, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput},
    };
    use itertools::Itertools;

    fn tx_with_subnetwork(subnetwork_id: SubnetworkId, id_word: u64) -> Transaction {
        let input = TransactionInput::new(
            TransactionOutpoint::new(TransactionId::from_u64_word(id_word), 0),
            vec![0x51],
            MAX_TX_IN_SEQUENCE_NUM,
            1,
        );
        let output = TransactionOutput::new(1, ScriptPublicKey::new(0, ScriptVec::from_slice(&[0x51])));
        let payload = if subnetwork_id == SUBNETWORK_ID_PAYLOAD { vec![id_word as u8] } else { vec![] };
        Transaction::new(TX_VERSION, vec![input], vec![output], 0, subnetwork_id, 0, payload)
    }

    #[test]
    fn sort_block_template_transactions_and_fees_by_subnetwork_keeps_fees_aligned() {
        let native = tx_with_subnetwork(SUBNETWORK_ID_NATIVE, 1);
        let payload_a = tx_with_subnetwork(SUBNETWORK_ID_PAYLOAD, 2);
        let payload_b = tx_with_subnetwork(SUBNETWORK_ID_PAYLOAD, 3);
        let native_id = native.id();
        let payload_a_id = payload_a.id();
        let payload_b_id = payload_b.id();

        let mut txs = vec![payload_a, native, payload_b];
        let mut fees = vec![20, 10, 30];
        VirtualStateProcessor::sort_block_template_transactions_and_fees_by_subnetwork(&mut txs, &mut fees);

        assert_eq!(txs.iter().map(|tx| tx.id()).collect_vec(), vec![native_id, payload_a_id, payload_b_id]);
        assert_eq!(fees, vec![10, 20, 30]);
    }
}

enum MergesetIncreaseResult {
    Accepted { increase_size: u64 },
    Rejected { new_candidate: Hash },
}
