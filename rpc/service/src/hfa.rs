use async_trait::async_trait;
use cryptix_consensus_core::{
    api::args::TransactionValidationArgs,
    errors::tx::TxRuleError,
    hashing::tx::hash as hash_tx,
    tx::{MutableTransaction, Transaction, TransactionOutpoint},
};
use cryptix_consensusmanager::ConsensusProxy;
use cryptix_core::time::unix_now;
use cryptix_core::{info, warn};
use cryptix_hashes::{HasherBase, TransactionHash};
use cryptix_mining::{
    manager::MiningManagerProxy,
    mempool::tx::{Orphan, Priority, RbfPolicy},
    model::tx_query::TransactionQuery,
};
use cryptix_p2p_flows::hfa::{FastIntentP2pData, FastMicroblockP2pData, HfaP2pBridge};
use cryptix_rpc_core::{
    CancelFastIntentRequest, CancelFastIntentResponse, GetFastIntentStatusRequest, GetFastIntentStatusResponse, RpcFastIntentStatus,
    RpcHash, RpcTransaction, SubmitFastIntentRequest, SubmitFastIntentResponse,
};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

const REASON_TEMPORARILY_REJECTED_FAST_LOCK_CONFLICT: &str = "temporarily_rejected_fast_lock_conflict";
const REASON_CLOCK_DRIFT_EXCEEDED: &str = "clock_drift_exceeded";
const REASON_FEE_RATE_BELOW_FLOOR: &str = "fee_rate_below_floor";
const REASON_MAX_FEE_EXCEEDED: &str = "max_fee_exceeded";
const REASON_TTL_EXPIRED: &str = "ttl_expired";
const REASON_RAIL_OVERLOADED: &str = "rail_overloaded";
const REASON_RAIL_DISABLED: &str = "rail_disabled";
const REASON_NODE_UNSYNCED: &str = "node_unsynced";
const REASON_NODE_RESTART: &str = "node_restart";
const REASON_INVALID_BASE_TX: &str = "invalid_base_tx";
const REASON_DUPLICATE_INTENT: &str = "duplicate_intent";
const REASON_DUPLICATE_BASE_TX_ACTIVE: &str = "duplicate_base_tx_active";
const REASON_MISSING_INPUTS: &str = "missing_inputs";
const REASON_NONSTANDARD_BASE_TX: &str = "nonstandard_base_tx";
const REASON_BASE_TX_ALREADY_IN_MEMPOOL: &str = "base_tx_already_in_mempool";
const REASON_BASE_TX_ALREADY_ONCHAIN: &str = "base_tx_already_onchain";
const REASON_INVALIDATED_BY_CHAIN_UPDATE: &str = "invalidated_by_chain_update";
const REASON_CANCEL_TOKEN_INVALID: &str = "cancel_token_invalid";
const REASON_CANCEL_UNAUTHORIZED: &str = "cancel_unauthorized";
const REASON_CANCELLED_BY_USER: &str = "cancelled_by_user";

const DEFAULT_FAST_TTL_MS: u64 = 3000;
const DEFAULT_CLOCK_DRIFT_MAX_MS: u64 = 5_000;
const DEFAULT_TERMINAL_RETENTION_MS: u64 = 120_000;
const DEFAULT_MAX_PENDING_INTENTS: usize = 50_000;
const DEFAULT_MAX_LOCKS: usize = 200_000;
const DEFAULT_MAX_TERMINAL_ENTRIES: usize = 200_000;
const DEFAULT_MAX_TERMINAL_BYTES: usize = 128 * 1024 * 1024;
const DEFAULT_MAX_INPUTS_PER_INTENT: usize = 32;
const DEFAULT_MAX_OUTPUTS_PER_INTENT: usize = 64;
const DEFAULT_MIN_FEERATE_FLOOR: f64 = 2.0;
const MIN_FEERATE_FLOOR_MULTIPLIER: f64 = 2.0;
const DEFAULT_SEEN_CACHE_TTL_MS: u64 = 600_000;
const DEFAULT_MICROBLOCK_INTERVAL_MS_NORMAL: u64 = 50;
const DEFAULT_MICROBLOCK_INTERVAL_MS_DEGRADED: u64 = 200;
const DEFAULT_REVALIDATION_BUDGET_NORMAL: usize = 64;
const DEFAULT_REVALIDATION_BUDGET_DEGRADED: usize = 16;
const DEFAULT_NORMAL_ARBITER_QUEUE_CAPACITY: usize = 4096;
const DEFAULT_FAST_ARBITER_QUEUE_CAPACITY: usize = 4096;
const REMOTE_MICROBLOCK_HINT_TTL_MS: u64 = 1_000;
const MODE_SAMPLE_WINDOW_MS: u64 = 10_000;
const ARBITER_SAMPLE_WINDOW_MS: u64 = 10_000;
const REMOTE_SOFT_DRIFT_TOLERANCE_MS: u64 = 30_000;

#[derive(Clone, Debug)]
pub struct HfaRuntimeConfig {
    pub enabled: bool,
    pub cpu_low_water_ratio: f64,
    pub fast_ttl_ms: u64,
    pub clock_drift_max_ms: u64,
    pub terminal_retention_ms: u64,
    pub max_pending_intents: usize,
    pub max_locks: usize,
    pub max_terminal_entries: usize,
    pub max_terminal_bytes: usize,
    pub max_inputs_per_intent: usize,
    pub max_outputs_per_intent: usize,
    pub min_feerate_floor: f64,
    pub seen_cache_ttl_ms: u64,
    pub microblock_interval_ms_normal: u64,
    pub microblock_interval_ms_degraded: u64,
    pub revalidation_budget_normal: usize,
    pub revalidation_budget_degraded: usize,
    pub normal_arbiter_queue_capacity: usize,
    pub fast_arbiter_queue_capacity: usize,
}

impl HfaRuntimeConfig {
    pub fn new(enabled: bool, cpu_low_water_ratio: f64) -> Self {
        Self {
            enabled,
            cpu_low_water_ratio,
            fast_ttl_ms: DEFAULT_FAST_TTL_MS,
            clock_drift_max_ms: DEFAULT_CLOCK_DRIFT_MAX_MS,
            terminal_retention_ms: DEFAULT_TERMINAL_RETENTION_MS,
            max_pending_intents: DEFAULT_MAX_PENDING_INTENTS,
            max_locks: DEFAULT_MAX_LOCKS,
            max_terminal_entries: DEFAULT_MAX_TERMINAL_ENTRIES,
            max_terminal_bytes: DEFAULT_MAX_TERMINAL_BYTES,
            max_inputs_per_intent: DEFAULT_MAX_INPUTS_PER_INTENT,
            max_outputs_per_intent: DEFAULT_MAX_OUTPUTS_PER_INTENT,
            min_feerate_floor: DEFAULT_MIN_FEERATE_FLOOR,
            seen_cache_ttl_ms: DEFAULT_SEEN_CACHE_TTL_MS,
            microblock_interval_ms_normal: DEFAULT_MICROBLOCK_INTERVAL_MS_NORMAL,
            microblock_interval_ms_degraded: DEFAULT_MICROBLOCK_INTERVAL_MS_DEGRADED,
            revalidation_budget_normal: DEFAULT_REVALIDATION_BUDGET_NORMAL,
            revalidation_budget_degraded: DEFAULT_REVALIDATION_BUDGET_DEGRADED,
            normal_arbiter_queue_capacity: DEFAULT_NORMAL_ARBITER_QUEUE_CAPACITY,
            fast_arbiter_queue_capacity: DEFAULT_FAST_ARBITER_QUEUE_CAPACITY,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HfaMode {
    Normal,
    Degraded,
    Paused,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FastIngressSource {
    Rpc,
    P2p,
}

#[derive(Clone, Debug)]
struct IntentRecord {
    intent_id: RpcHash,
    status: RpcFastIntentStatus,
    reason: Option<String>,
    node_epoch: u64,
    base_tx: Option<RpcTransaction>,
    intent_nonce: u64,
    client_created_at_ms: u64,
    max_fee: u64,
    expires_at_ms: Option<u64>,
    confirm_after_ms: Option<u64>,
    retention_until_ms: Option<u64>,
    terminal_entered_at_ms: Option<u64>,
    cancel_token: Option<String>,
    base_tx_fingerprint: RpcHash,
    inputs: Vec<TransactionOutpoint>,
    estimated_bytes: usize,
    p2p_relayed: bool,
}

impl IntentRecord {
    fn new_prelock_received(
        intent_id: RpcHash,
        node_epoch: u64,
        base_tx: Option<RpcTransaction>,
        intent_nonce: u64,
        client_created_at_ms: u64,
        max_fee: u64,
        base_tx_fingerprint: RpcHash,
    ) -> Self {
        let estimated_bytes = estimate_record_bytes(base_tx.as_ref());
        Self {
            intent_id,
            status: RpcFastIntentStatus::Received,
            reason: None,
            node_epoch,
            base_tx,
            intent_nonce,
            client_created_at_ms,
            max_fee,
            expires_at_ms: None,
            confirm_after_ms: None,
            retention_until_ms: None,
            terminal_entered_at_ms: None,
            cancel_token: None,
            base_tx_fingerprint,
            inputs: Vec::new(),
            estimated_bytes,
            p2p_relayed: false,
        }
    }
}

#[derive(Debug)]
struct HfaState {
    node_epoch: u64,
    mode: HfaMode,
    prelock: HashMap<RpcHash, IntentRecord>,
    active: HashMap<RpcHash, IntentRecord>,
    terminal: HashMap<RpcHash, IntentRecord>,
    active_fingerprint: HashMap<RpcHash, RpcHash>,
    input_locks: HashMap<TransactionOutpoint, RpcHash>,
    seen_cache: HashMap<RpcHash, u64>,
    remote_microblock_hints: HashMap<RpcHash, u64>,
    outbound_microblocks: Vec<FastMicroblockP2pData>,
    revalidation_queue: VecDeque<RpcHash>,
    fast_tx_routes: HashMap<RpcHash, u64>,
    submit_total: u64,
    submit_rpc_total: u64,
    submit_p2p_total: u64,
    overload_reject_total: u64,
    normal_conflict_reject_total: u64,
    rejected_total: u64,
    dropped_total: u64,
    expired_total: u64,
    pull_miss_total: u64,
    pull_fail_total: u64,
    fast_arbiter_queue_len: usize,
    normal_arbiter_queue_len: usize,
    fast_arbiter_wait_samples_ms: VecDeque<(u64, u64)>,
    fast_arbiter_hold_samples_ms: VecDeque<(u64, u64)>,
    latest_fast_arbiter_wait_ms_p95: f64,
    latest_fast_arbiter_hold_ms_p95: f64,
    basechain_block_latency_ms: f64,
    basechain_latency_baseline_ms: f64,
    basechain_latency_delta_vs_baseline_ms: f64,
    basechain_latency_delta_ratio: f64,
    mode_transition_total: u64,
    mode_transition_normal_to_degraded_total: u64,
    mode_transition_degraded_to_paused_total: u64,
    mode_transition_paused_to_degraded_total: u64,
    mode_transition_degraded_to_normal_total: u64,
    terminal_evictions_retention_total: u64,
    terminal_evictions_expired_total: u64,
    terminal_evictions_oldest_total: u64,
    mode_samples: VecDeque<ModeSample>,
    last_mode_eval_ms: u64,
    degrade_trigger_streak: u64,
    pause_trigger_streak: u64,
    pause_recovery_streak: u64,
    normal_recovery_streak: u64,
    terminal_bytes: usize,
    paused_since_ms: Option<u64>,
    paused_stuck_alerted: bool,
}

#[derive(Debug, Clone, Copy)]
struct ModeSample {
    ts_ms: u64,
    submit_total: u64,
    overload_reject_total: u64,
    pull_fail_total: u64,
    queue_ratio: f64,
    validation_queue_ratio: f64,
    arbiter_wait_p95_ms: f64,
    arbiter_hold_p95_ms: f64,
    cpu_ratio: f64,
    revalidation_backlog_seconds: f64,
    basechain_latency_delta_ratio: f64,
    basechain_block_latency_ms: f64,
    basechain_latency_delta_vs_baseline_ms: f64,
}

impl HfaState {
    fn new(node_epoch: u64) -> Self {
        Self {
            node_epoch,
            mode: HfaMode::Normal,
            prelock: HashMap::new(),
            active: HashMap::new(),
            terminal: HashMap::new(),
            active_fingerprint: HashMap::new(),
            input_locks: HashMap::new(),
            seen_cache: HashMap::new(),
            remote_microblock_hints: HashMap::new(),
            outbound_microblocks: Vec::new(),
            revalidation_queue: VecDeque::new(),
            fast_tx_routes: HashMap::new(),
            submit_total: 0,
            submit_rpc_total: 0,
            submit_p2p_total: 0,
            overload_reject_total: 0,
            normal_conflict_reject_total: 0,
            rejected_total: 0,
            dropped_total: 0,
            expired_total: 0,
            pull_miss_total: 0,
            pull_fail_total: 0,
            fast_arbiter_queue_len: 0,
            normal_arbiter_queue_len: 0,
            fast_arbiter_wait_samples_ms: VecDeque::new(),
            fast_arbiter_hold_samples_ms: VecDeque::new(),
            latest_fast_arbiter_wait_ms_p95: 0.0,
            latest_fast_arbiter_hold_ms_p95: 0.0,
            basechain_block_latency_ms: 0.0,
            basechain_latency_baseline_ms: 0.0,
            basechain_latency_delta_vs_baseline_ms: 0.0,
            basechain_latency_delta_ratio: 0.0,
            mode_transition_total: 0,
            mode_transition_normal_to_degraded_total: 0,
            mode_transition_degraded_to_paused_total: 0,
            mode_transition_paused_to_degraded_total: 0,
            mode_transition_degraded_to_normal_total: 0,
            terminal_evictions_retention_total: 0,
            terminal_evictions_expired_total: 0,
            terminal_evictions_oldest_total: 0,
            mode_samples: VecDeque::new(),
            last_mode_eval_ms: 0,
            degrade_trigger_streak: 0,
            pause_trigger_streak: 0,
            pause_recovery_streak: 0,
            normal_recovery_streak: 0,
            terminal_bytes: 0,
            paused_since_ms: None,
            paused_stuck_alerted: false,
        }
    }
}

#[derive(Debug)]
pub struct HfaEngine {
    config: HfaRuntimeConfig,
    state: Mutex<HfaState>,
    fast_arbiter_inflight: AtomicUsize,
}

#[derive(Clone, Debug)]
pub struct HfaMetricsSnapshot {
    pub enabled: bool,
    pub node_epoch: u64,
    pub mode: &'static str,
    pub paused_for_ms: u64,
    pub active_locks: usize,
    pub prelock_intents: usize,
    pub active_intents: usize,
    pub pending_intents: usize,
    pub terminal_entries: usize,
    pub terminal_bytes: usize,
    pub submit_total: u64,
    pub submit_rpc_total: u64,
    pub submit_p2p_total: u64,
    pub rejected_total: u64,
    pub overload_reject_total: u64,
    pub normal_conflict_reject_total: u64,
    pub dropped_total: u64,
    pub expired_total: u64,
    pub pull_miss_total: u64,
    pub pull_fail_total: u64,
    pub fast_arbiter_queue_len: usize,
    pub fast_arbiter_wait_ms: f64,
    pub fast_arbiter_hold_ms: f64,
    pub basechain_block_latency_ms: f64,
    pub basechain_latency_delta_vs_baseline_ms: f64,
    pub mode_transition_total: u64,
    pub mode_transition_normal_to_degraded_total: u64,
    pub mode_transition_degraded_to_paused_total: u64,
    pub mode_transition_paused_to_degraded_total: u64,
    pub mode_transition_degraded_to_normal_total: u64,
    pub terminal_evictions_retention_total: u64,
    pub terminal_evictions_expired_total: u64,
    pub terminal_evictions_oldest_total: u64,
    pub fast_arbiter_queue_ratio: f64,
    pub fast_validation_queue_ratio: f64,
    pub fast_worker_cpu_ratio: f64,
    pub revalidation_backlog_seconds: f64,
}

struct FastArbiterInflightTicket<'a> {
    counter: &'a AtomicUsize,
}

impl<'a> FastArbiterInflightTicket<'a> {
    fn new(counter: &'a AtomicUsize) -> Self {
        Self { counter }
    }
}

impl Drop for FastArbiterInflightTicket<'_> {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

impl HfaEngine {
    pub fn new(config: HfaRuntimeConfig) -> Self {
        let node_epoch = unix_now();
        Self { config, state: Mutex::new(HfaState::new(node_epoch)), fast_arbiter_inflight: AtomicUsize::new(0) }
    }

    pub fn config(&self) -> &HfaRuntimeConfig {
        &self.config
    }

    pub fn effective_feerate_floor(&self, minimum_relay_feerate: f64) -> f64 {
        self.config.min_feerate_floor.max(minimum_relay_feerate.max(0.0) * MIN_FEERATE_FLOOR_MULTIPLIER)
    }

    pub fn node_epoch(&self) -> u64 {
        self.lock_state().node_epoch
    }

    pub async fn submit_fast_intent(
        &self,
        network_id: &str,
        request: SubmitFastIntentRequest,
        session: ConsensusProxy,
        mining_manager: MiningManagerProxy,
        is_synced: bool,
        cpu_ratio: f64,
        basechain_block_latency_ms: f64,
        source: FastIngressSource,
    ) -> SubmitFastIntentResponse {
        let now_ms = unix_now();
        let cpu_ratio = cpu_ratio.clamp(0.0, 1.0);
        self.revalidate_active_budgeted(session.clone(), is_synced, cpu_ratio, basechain_block_latency_ms).await;

        let tentative_intent_id = derive_intent_id_from_rpc_tx(
            network_id,
            &request.base_tx,
            request.intent_nonce,
            request.client_created_at_ms,
            request.max_fee,
        );

        // 1) Rail enabled, mode, sync state
        {
            let mut state = self.lock_state();
            self.sweep(&mut state, now_ms);
            self.update_mode(&mut state, cpu_ratio, is_synced, basechain_block_latency_ms, now_ms);
            state.submit_total = state.submit_total.saturating_add(1);
            match source {
                FastIngressSource::Rpc => state.submit_rpc_total = state.submit_rpc_total.saturating_add(1),
                FastIngressSource::P2p => state.submit_p2p_total = state.submit_p2p_total.saturating_add(1),
            }
            if !self.config.enabled {
                return self.submit_rejected_with_state(&state, tentative_intent_id, REASON_RAIL_DISABLED, None);
            }
            if state.mode == HfaMode::Paused {
                return self.submit_rejected_with_state(&state, tentative_intent_id, REASON_RAIL_OVERLOADED, None);
            }
            if !is_synced {
                return self.submit_rejected_with_state(&state, tentative_intent_id, REASON_NODE_UNSYNCED, None);
            }
        }

        let tx: Transaction = match request.base_tx.clone().try_into() {
            Ok(tx) => tx,
            Err(_) => {
                return self.submit_rejected(tentative_intent_id, REASON_INVALID_BASE_TX, now_ms, None);
            }
        };

        let base_tx_fingerprint = hash_tx(&tx, false);
        let intent_id =
            derive_intent_id(network_id, base_tx_fingerprint, request.intent_nonce, request.client_created_at_ms, request.max_fee);

        // 2) Structure checks
        if tx.inputs.len() > self.config.max_inputs_per_intent || tx.outputs.len() > self.config.max_outputs_per_intent {
            return self.submit_rejected(intent_id, REASON_NONSTANDARD_BASE_TX, now_ms, None);
        }

        // 3) Duplicate / seen / fingerprint short-circuit
        {
            let mut state = self.lock_state();
            self.sweep(&mut state, now_ms);
            if let Some(existing) =
                state.prelock.get(&intent_id).or_else(|| state.active.get(&intent_id)).or_else(|| state.terminal.get(&intent_id))
            {
                return self.snapshot_submit(existing.clone());
            }
            if state.seen_cache.contains_key(&intent_id) {
                return self.submit_rejected_with_state(&state, intent_id, REASON_DUPLICATE_INTENT, None);
            }
            if state.active_fingerprint.get(&base_tx_fingerprint).is_some() {
                return self.submit_rejected_with_state(&state, intent_id, REASON_DUPLICATE_BASE_TX_ACTIVE, None);
            }
            let queue_limit = match state.mode {
                HfaMode::Normal => self.config.max_pending_intents,
                HfaMode::Degraded => self.config.max_pending_intents / 2,
                HfaMode::Paused => 0,
            };
            if state.prelock.len() + state.active.len() >= queue_limit {
                return self.submit_rejected_with_state(&state, intent_id, REASON_RAIL_OVERLOADED, None);
            }
            let pre = IntentRecord::new_prelock_received(
                intent_id,
                state.node_epoch,
                Some(request.base_tx.clone()),
                request.intent_nonce,
                request.client_created_at_ms,
                request.max_fee,
                base_tx_fingerprint,
            );
            state.prelock.insert(intent_id, pre);
        }

        // 4) Drift / time rules
        let drift = now_ms.abs_diff(request.client_created_at_ms);
        if drift > self.config.clock_drift_max_ms {
            if matches!(source, FastIngressSource::P2p) {
                if drift > REMOTE_SOFT_DRIFT_TOLERANCE_MS {
                    let mut state = self.lock_state();
                    return self.reject_from_prelock(&mut state, intent_id, REASON_CLOCK_DRIFT_EXCEEDED, now_ms);
                }
                // Remote peers can have clock skew. Keep fast propagation resilient by not hard-rejecting
                // remote intents solely on drift if all other validation passes.
                warn!(
                    "Fastchain receive drift tolerance: intent {} drift={}ms exceeds {}ms (accepting with soft drift)",
                    intent_id, drift, self.config.clock_drift_max_ms
                );
            } else {
                let mut state = self.lock_state();
                return self.reject_from_prelock(&mut state, intent_id, REASON_CLOCK_DRIFT_EXCEEDED, now_ms);
            }
        }

        // 5) Policy preconditions
        if request.max_fee == 0 {
            let mut state = self.lock_state();
            return self.reject_from_prelock(&mut state, intent_id, REASON_MAX_FEE_EXCEEDED, now_ms);
        }
        let minimum_relay_feerate = mining_manager.clone().minimum_relay_feerate().await.max(0.0);
        let effective_feerate_floor = self.config.min_feerate_floor.max(minimum_relay_feerate * MIN_FEERATE_FLOOR_MULTIPLIER);

        // 6) Full base transaction validation
        if mining_manager.clone().has_transaction(tx.id(), TransactionQuery::All).await {
            let mut state = self.lock_state();
            return self.reject_from_prelock(&mut state, intent_id, REASON_BASE_TX_ALREADY_IN_MEMPOOL, now_ms);
        }
        if mining_manager.clone().has_accepted_transaction(tx.id()).await {
            let mut state = self.lock_state();
            return self.reject_from_prelock(&mut state, intent_id, REASON_BASE_TX_ALREADY_ONCHAIN, now_ms);
        }

        let mut mtx = MutableTransaction::from_tx(tx.clone());
        let validation_result = session
            .clone()
            .spawn_blocking(move |c| c.validate_mempool_transaction(&mut mtx, &TransactionValidationArgs::default()).map(|_| mtx))
            .await;

        let mtx = match validation_result {
            Ok(mtx) => mtx,
            Err(err) => {
                let reason = map_tx_error_to_reason(err);
                let mut state = self.lock_state();
                return self.reject_from_prelock(&mut state, intent_id, reason, now_ms);
            }
        };

        let calculated_fee = mtx.calculated_fee.unwrap_or(0);
        if calculated_fee > request.max_fee {
            let mut state = self.lock_state();
            return self.reject_from_prelock(&mut state, intent_id, REASON_MAX_FEE_EXCEEDED, now_ms);
        }
        let feerate = mtx.calculated_feerate().unwrap_or(0.0);
        if feerate < effective_feerate_floor {
            let mut state = self.lock_state();
            return self.reject_from_prelock(&mut state, intent_id, REASON_FEE_RATE_BELOW_FLOOR, now_ms);
        }

        {
            let mut state = self.lock_state();
            if let Some(pre) = state.prelock.get_mut(&intent_id) {
                pre.status = RpcFastIntentStatus::Validated;
            }
        }

        // 7) Arbiter conflict check
        // 8) Atomic input lock acquisition
        let expires_at_ms = now_ms.saturating_add(self.config.fast_ttl_ms);
        let retention_until_ms = expires_at_ms.saturating_add(self.config.terminal_retention_ms);
        let inputs: Vec<TransactionOutpoint> = tx.inputs.iter().map(|i| i.previous_outpoint).collect();

        let inflight_before = self.fast_arbiter_inflight.fetch_add(1, Ordering::SeqCst);
        if inflight_before >= self.config.fast_arbiter_queue_capacity {
            self.fast_arbiter_inflight.fetch_sub(1, Ordering::SeqCst);
            let mut state = self.lock_state();
            self.sync_fast_arbiter_queue_len(&mut state);
            return self.reject_from_prelock(&mut state, intent_id, REASON_RAIL_OVERLOADED, now_ms);
        }
        let fast_arbiter_ticket = FastArbiterInflightTicket::new(&self.fast_arbiter_inflight);

        let arbiter_wait_started_ms = unix_now();
        let mut state = self.lock_state();
        self.sync_fast_arbiter_queue_len(&mut state);
        let arbiter_wait_ms = unix_now().saturating_sub(arbiter_wait_started_ms);
        let arbiter_hold_started_ms = unix_now();
        self.sweep(&mut state, now_ms);
        self.update_mode(&mut state, cpu_ratio, is_synced, basechain_block_latency_ms, now_ms);

        if !self.config.enabled {
            let response = self.reject_from_prelock(&mut state, intent_id, REASON_RAIL_DISABLED, now_ms);
            self.finish_fast_arbiter_section(&mut state, now_ms, arbiter_wait_ms, unix_now().saturating_sub(arbiter_hold_started_ms));
            return response;
        }
        if state.mode == HfaMode::Paused {
            let response = self.reject_from_prelock(&mut state, intent_id, REASON_RAIL_OVERLOADED, now_ms);
            self.finish_fast_arbiter_section(&mut state, now_ms, arbiter_wait_ms, unix_now().saturating_sub(arbiter_hold_started_ms));
            return response;
        }
        if state.active_fingerprint.get(&base_tx_fingerprint).is_some() {
            let response = self.reject_from_prelock(&mut state, intent_id, REASON_DUPLICATE_BASE_TX_ACTIVE, now_ms);
            self.finish_fast_arbiter_section(&mut state, now_ms, arbiter_wait_ms, unix_now().saturating_sub(arbiter_hold_started_ms));
            return response;
        }

        if inputs.iter().any(|input| state.input_locks.contains_key(input)) {
            let response = self.reject_from_prelock(&mut state, intent_id, REASON_TEMPORARILY_REJECTED_FAST_LOCK_CONFLICT, now_ms);
            self.finish_fast_arbiter_section(&mut state, now_ms, arbiter_wait_ms, unix_now().saturating_sub(arbiter_hold_started_ms));
            return response;
        }
        if state.input_locks.len().saturating_add(inputs.len()) > self.config.max_locks {
            let response = self.reject_from_prelock(&mut state, intent_id, REASON_RAIL_OVERLOADED, now_ms);
            self.finish_fast_arbiter_section(&mut state, now_ms, arbiter_wait_ms, unix_now().saturating_sub(arbiter_hold_started_ms));
            return response;
        }

        for input in &inputs {
            state.input_locks.insert(*input, intent_id);
        }
        state.active_fingerprint.insert(base_tx_fingerprint, intent_id);
        state.seen_cache.insert(intent_id, now_ms.saturating_add(self.config.seen_cache_ttl_ms));

        // 9) Store active state
        let cancel_token = build_cancel_token(intent_id, state.node_epoch, now_ms);
        let confirm_after_ms = now_ms.saturating_add(self.microblock_interval_ms_for_mode(state.mode));
        let mut active = state.prelock.remove(&intent_id).unwrap_or_else(|| {
            IntentRecord::new_prelock_received(
                intent_id,
                state.node_epoch,
                Some(request.base_tx.clone()),
                request.intent_nonce,
                request.client_created_at_ms,
                request.max_fee,
                base_tx_fingerprint,
            )
        });
        active.inputs = inputs;
        active.base_tx = Some(request.base_tx.clone());
        active.cancel_token = Some(cancel_token.clone());
        active.expires_at_ms = Some(expires_at_ms);
        active.retention_until_ms = Some(retention_until_ms);
        active.confirm_after_ms = Some(confirm_after_ms);
        active.terminal_entered_at_ms = None;
        active.status = RpcFastIntentStatus::Locked;
        active.reason = None;
        active.estimated_bytes = estimate_record_bytes(active.base_tx.as_ref());

        // 10) local microbatching => status becomes fast_confirmed only after local cadence,
        // unless a bounded remote microblock hint already exists for this intent.
        if state.remote_microblock_hints.get(&intent_id).is_some_and(|hint_until_ms| *hint_until_ms >= now_ms) {
            state.remote_microblock_hints.remove(&intent_id);
            active.status = RpcFastIntentStatus::FastConfirmed;
            active.confirm_after_ms = None;
        }
        state.active.insert(intent_id, active.clone());
        state.revalidation_queue.push_back(intent_id);
        self.finish_fast_arbiter_section(&mut state, now_ms, arbiter_wait_ms, unix_now().saturating_sub(arbiter_hold_started_ms));
        drop(fast_arbiter_ticket);
        self.sync_fast_arbiter_queue_len(&mut state);

        SubmitFastIntentResponse {
            intent_id,
            status: active.status,
            reason: None,
            base_tx_id: Some(tx.id()),
            node_epoch: state.node_epoch,
            expires_at_ms: Some(expires_at_ms),
            retention_until_ms: Some(retention_until_ms),
            cancel_token: Some(cancel_token),
            basechain_submitted: false,
        }
    }

    pub fn get_fast_intent_status(&self, request: GetFastIntentStatusRequest) -> GetFastIntentStatusResponse {
        let now_ms = unix_now();
        let mut state = self.lock_state();
        self.sweep(&mut state, now_ms);

        if let Some(entry) = state
            .prelock
            .get(&request.intent_id)
            .or_else(|| state.active.get(&request.intent_id))
            .or_else(|| state.terminal.get(&request.intent_id))
        {
            return GetFastIntentStatusResponse {
                status: entry.status,
                reason: entry.reason.clone(),
                base_tx_id: derive_base_tx_id_from_record(entry),
                node_epoch: state.node_epoch,
                expires_at_ms: entry.expires_at_ms,
                retention_until_ms: entry.retention_until_ms,
                cancel_token: entry.cancel_token.clone(),
                epoch_changed: request.client_last_node_epoch.map(|epoch| epoch != state.node_epoch),
            };
        }

        GetFastIntentStatusResponse {
            status: RpcFastIntentStatus::UnknownIntent,
            reason: None,
            base_tx_id: None,
            node_epoch: state.node_epoch,
            expires_at_ms: None,
            retention_until_ms: None,
            cancel_token: None,
            epoch_changed: request.client_last_node_epoch.map(|epoch| epoch != state.node_epoch),
        }
    }

    pub fn cancel_fast_intent(&self, request: CancelFastIntentRequest) -> CancelFastIntentResponse {
        let now_ms = unix_now();
        let mut state = self.lock_state();
        self.sweep(&mut state, now_ms);

        if let Some(entry) = state.terminal.get(&request.intent_id) {
            return CancelFastIntentResponse {
                status: entry.status,
                reason: entry.reason.clone(),
                node_epoch: state.node_epoch,
                retention_until_ms: entry.retention_until_ms,
                epoch_changed: None,
            };
        }

        let epoch_changed = request.node_epoch != state.node_epoch;
        if let Some(active) = state.active.get(&request.intent_id).cloned() {
            if epoch_changed {
                return CancelFastIntentResponse {
                    status: RpcFastIntentStatus::Rejected,
                    reason: Some(REASON_NODE_RESTART.to_string()),
                    node_epoch: state.node_epoch,
                    retention_until_ms: None,
                    epoch_changed: None,
                };
            }

            let Some(expected_token) = active.cancel_token.clone() else {
                return CancelFastIntentResponse {
                    status: RpcFastIntentStatus::Rejected,
                    reason: Some(REASON_CANCEL_UNAUTHORIZED.to_string()),
                    node_epoch: state.node_epoch,
                    retention_until_ms: None,
                    epoch_changed: None,
                };
            };

            if expected_token != request.cancel_token {
                return CancelFastIntentResponse {
                    status: RpcFastIntentStatus::Rejected,
                    reason: Some(REASON_CANCEL_TOKEN_INVALID.to_string()),
                    node_epoch: state.node_epoch,
                    retention_until_ms: None,
                    epoch_changed: None,
                };
            }

            let record = self.transition_active_to_terminal(
                &mut state,
                request.intent_id,
                RpcFastIntentStatus::Cancelled,
                Some(REASON_CANCELLED_BY_USER.to_string()),
                now_ms,
            );
            return CancelFastIntentResponse {
                status: record.status,
                reason: record.reason,
                node_epoch: state.node_epoch,
                retention_until_ms: record.retention_until_ms,
                epoch_changed: None,
            };
        }

        if state.prelock.contains_key(&request.intent_id) {
            if epoch_changed {
                return CancelFastIntentResponse {
                    status: RpcFastIntentStatus::Rejected,
                    reason: Some(REASON_NODE_RESTART.to_string()),
                    node_epoch: state.node_epoch,
                    retention_until_ms: None,
                    epoch_changed: None,
                };
            }
            return CancelFastIntentResponse {
                status: RpcFastIntentStatus::Rejected,
                reason: Some(REASON_CANCEL_UNAUTHORIZED.to_string()),
                node_epoch: state.node_epoch,
                retention_until_ms: None,
                epoch_changed: None,
            };
        }

        CancelFastIntentResponse {
            status: RpcFastIntentStatus::UnknownIntent,
            reason: None,
            node_epoch: state.node_epoch,
            retention_until_ms: None,
            epoch_changed: Some(epoch_changed),
        }
    }

    pub fn has_intent(&self, intent_id: RpcHash) -> bool {
        let now_ms = unix_now();
        let mut state = self.lock_state();
        self.sweep(&mut state, now_ms);
        state.prelock.contains_key(&intent_id) || state.active.contains_key(&intent_id) || state.terminal.contains_key(&intent_id)
    }

    pub fn mark_fast_tx_route(&self, tx_id: RpcHash) {
        let now_ms = unix_now();
        let mut state = self.lock_state();
        self.sweep(&mut state, now_ms);
        let retention_ms = self.config.seen_cache_ttl_ms.max(self.config.terminal_retention_ms).max(60_000);
        state.fast_tx_routes.insert(tx_id, now_ms.saturating_add(retention_ms));
    }

    pub fn is_fast_tx_route(&self, tx_id: RpcHash) -> bool {
        let now_ms = unix_now();
        let mut state = self.lock_state();
        self.sweep(&mut state, now_ms);
        state.fast_tx_routes.get(&tx_id).is_some_and(|until_ms| *until_ms > now_ms)
    }

    pub fn recent_fast_tx_route_ids(&self, limit: usize) -> Vec<RpcHash> {
        let now_ms = unix_now();
        let mut state = self.lock_state();
        self.sweep(&mut state, now_ms);

        let mut pairs = state.fast_tx_routes.iter().map(|(tx_id, until_ms)| (tx_id.clone(), *until_ms)).collect::<Vec<_>>();

        pairs.sort_by(|a, b| b.1.cmp(&a.1));
        pairs.into_iter().take(limit).map(|(tx_id, _)| tx_id).collect()
    }

    pub fn get_fast_intents_for_p2p(&self, intent_ids: &[RpcHash]) -> Vec<FastIntentP2pData> {
        let now_ms = unix_now();
        let mut state = self.lock_state();
        self.sweep(&mut state, now_ms);

        intent_ids
            .iter()
            .filter_map(|intent_id| {
                let record =
                    state.prelock.get(intent_id).or_else(|| state.active.get(intent_id)).or_else(|| state.terminal.get(intent_id))?;
                // Do not relay terminal-rejected/cancelled/expired contexts.
                // Pull-on-miss should only recover intents that can still provide meaningful fast-path context.
                if matches!(
                    record.status,
                    RpcFastIntentStatus::Rejected
                        | RpcFastIntentStatus::Cancelled
                        | RpcFastIntentStatus::Expired
                        | RpcFastIntentStatus::Dropped
                        | RpcFastIntentStatus::UnknownIntent
                ) {
                    return None;
                }
                let base_tx = record.base_tx.clone()?;
                let tx: Transaction = base_tx.try_into().ok()?;
                Some(FastIntentP2pData {
                    intent_id: *intent_id,
                    base_tx: tx,
                    intent_nonce: record.intent_nonce,
                    client_created_at_ms: record.client_created_at_ms,
                    max_fee: record.max_fee,
                })
            })
            .collect()
    }

    pub fn on_remote_fast_microblock(&self, intent_ids: &[RpcHash], now_ms: u64) -> Vec<RpcHash> {
        let mut state = self.lock_state();
        self.sweep(&mut state, now_ms);

        let mut missing = Vec::new();
        for intent_id in intent_ids {
            if let Some(active) = state.active.get_mut(intent_id) {
                if active.status == RpcFastIntentStatus::Locked {
                    active.status = RpcFastIntentStatus::FastConfirmed;
                    active.confirm_after_ms = None;
                }
                continue;
            }
            if state.prelock.contains_key(intent_id) || state.terminal.contains_key(intent_id) {
                state.remote_microblock_hints.insert(*intent_id, now_ms.saturating_add(REMOTE_MICROBLOCK_HINT_TTL_MS));
                continue;
            }
            state.remote_microblock_hints.insert(*intent_id, now_ms.saturating_add(REMOTE_MICROBLOCK_HINT_TTL_MS));
            missing.push(*intent_id);
        }

        if !missing.is_empty() {
            state.pull_miss_total = state.pull_miss_total.saturating_add(missing.len() as u64);
        }

        missing
    }

    pub fn record_pull_fail(&self, count: u64) {
        let mut state = self.lock_state();
        state.pull_fail_total = state.pull_fail_total.saturating_add(count);
    }

    pub fn take_outbound_fast_microblocks(&self) -> Vec<FastMicroblockP2pData> {
        let mut state = self.lock_state();
        std::mem::take(&mut state.outbound_microblocks)
    }

    pub fn should_broadcast_intent_once(&self, intent_id: RpcHash) -> bool {
        let mut state = self.lock_state();

        if let Some(record) = state.prelock.get_mut(&intent_id) {
            if record.p2p_relayed {
                return false;
            }
            record.p2p_relayed = true;
            return true;
        }
        if let Some(record) = state.active.get_mut(&intent_id) {
            if record.p2p_relayed {
                return false;
            }
            record.p2p_relayed = true;
            return true;
        }
        if let Some(record) = state.terminal.get_mut(&intent_id) {
            if record.p2p_relayed {
                return false;
            }
            record.p2p_relayed = true;
            return true;
        }
        false
    }

    pub fn has_fast_lock_conflict_for_inputs(&self, inputs: &[TransactionOutpoint]) -> bool {
        let now_ms = unix_now();
        let mut state = self.lock_state();
        state.normal_arbiter_queue_len =
            state.normal_arbiter_queue_len.saturating_add(1).min(self.config.normal_arbiter_queue_capacity);
        self.sweep(&mut state, now_ms);
        let has_conflict = inputs.iter().any(|input| state.input_locks.contains_key(input));
        if has_conflict {
            state.normal_conflict_reject_total = state.normal_conflict_reject_total.saturating_add(1);
        }
        state.normal_arbiter_queue_len = state.normal_arbiter_queue_len.saturating_sub(1);
        has_conflict
    }

    pub fn has_fast_lock_conflict_for_tx(&self, tx: &Transaction) -> bool {
        let now_ms = unix_now();
        let mut state = self.lock_state();
        state.normal_arbiter_queue_len =
            state.normal_arbiter_queue_len.saturating_add(1).min(self.config.normal_arbiter_queue_capacity);
        self.sweep(&mut state, now_ms);
        let tx_fingerprint = hash_tx(tx, false);
        let same_tx_owner = state.active_fingerprint.get(&tx_fingerprint).copied();
        let has_conflict = tx.inputs.iter().any(|input| {
            let Some(lock_owner) = state.input_locks.get(&input.previous_outpoint).copied() else {
                return false;
            };
            // Allow the exact same base transaction to pass through the normal path while its
            // own fast lock is active; only competing transactions should be blocked.
            Some(lock_owner) != same_tx_owner
        });
        if has_conflict {
            state.normal_conflict_reject_total = state.normal_conflict_reject_total.saturating_add(1);
        }
        state.normal_arbiter_queue_len = state.normal_arbiter_queue_len.saturating_sub(1);
        has_conflict
    }

    pub async fn revalidate_active_budgeted(
        &self,
        session: ConsensusProxy,
        is_synced: bool,
        cpu_ratio: f64,
        basechain_block_latency_ms: f64,
    ) {
        let now_ms = unix_now();
        let candidates: Vec<(RpcHash, Transaction)> = {
            let mut state = self.lock_state();
            self.sweep(&mut state, now_ms);
            self.update_mode(&mut state, cpu_ratio.clamp(0.0, 1.0), is_synced, basechain_block_latency_ms, now_ms);
            if !self.config.enabled || state.mode == HfaMode::Paused {
                return;
            }

            let budget = self.revalidation_budget_for_mode(state.mode);
            if budget == 0 || state.active.is_empty() {
                return;
            }

            if state.revalidation_queue.is_empty() {
                let ids: Vec<RpcHash> = state.active.keys().copied().collect();
                state.revalidation_queue.extend(ids);
            }

            let mut out = Vec::with_capacity(budget);
            let mut scanned = 0usize;
            let max_scan = state.revalidation_queue.len().saturating_add(budget);
            while out.len() < budget && scanned < max_scan {
                let Some(intent_id) = state.revalidation_queue.pop_front() else {
                    break;
                };
                scanned = scanned.saturating_add(1);

                let Some(active) = state.active.get(&intent_id).cloned() else {
                    continue;
                };
                state.revalidation_queue.push_back(intent_id);
                if !matches!(active.status, RpcFastIntentStatus::Locked | RpcFastIntentStatus::FastConfirmed) {
                    continue;
                }
                let Some(base_tx) = active.base_tx else {
                    continue;
                };
                let Ok(tx) = TryInto::<Transaction>::try_into(base_tx) else {
                    continue;
                };
                out.push((intent_id, tx));
            }

            out
        };

        if candidates.is_empty() {
            return;
        }

        let mut invalidated = Vec::new();
        for (intent_id, tx) in candidates {
            let mut mtx = MutableTransaction::from_tx(tx);
            let validation_result = session
                .clone()
                .spawn_blocking(move |c| c.validate_mempool_transaction(&mut mtx, &TransactionValidationArgs::default()))
                .await;
            if matches!(validation_result, Err(TxRuleError::MissingTxOutpoints)) {
                invalidated.push(intent_id);
            }
        }

        if invalidated.is_empty() {
            return;
        }
        invalidated.sort_unstable();
        invalidated.dedup();

        let now_ms = unix_now();
        let mut state = self.lock_state();
        self.sweep(&mut state, now_ms);
        for intent_id in invalidated {
            if state.active.contains_key(&intent_id) {
                let _ = self.transition_active_to_terminal(
                    &mut state,
                    intent_id,
                    RpcFastIntentStatus::Dropped,
                    Some(REASON_INVALIDATED_BY_CHAIN_UPDATE.to_string()),
                    now_ms,
                );
            }
        }
    }

    pub fn metrics_snapshot(&self) -> HfaMetricsSnapshot {
        let now_ms = unix_now();
        let mut state = self.lock_state();
        self.sweep(&mut state, now_ms);

        let latest = state.mode_samples.back().copied().unwrap_or(ModeSample {
            ts_ms: now_ms,
            submit_total: state.submit_total,
            overload_reject_total: state.overload_reject_total,
            pull_fail_total: state.pull_fail_total,
            queue_ratio: 0.0,
            validation_queue_ratio: 0.0,
            arbiter_wait_p95_ms: state.latest_fast_arbiter_wait_ms_p95,
            arbiter_hold_p95_ms: state.latest_fast_arbiter_hold_ms_p95,
            cpu_ratio: 0.0,
            revalidation_backlog_seconds: 0.0,
            basechain_latency_delta_ratio: state.basechain_latency_delta_ratio,
            basechain_block_latency_ms: state.basechain_block_latency_ms,
            basechain_latency_delta_vs_baseline_ms: state.basechain_latency_delta_vs_baseline_ms,
        });

        HfaMetricsSnapshot {
            enabled: self.config.enabled,
            node_epoch: state.node_epoch,
            mode: mode_name(state.mode),
            paused_for_ms: if state.mode == HfaMode::Paused {
                state.paused_since_ms.map(|paused_since_ms| now_ms.saturating_sub(paused_since_ms)).unwrap_or(0)
            } else {
                0
            },
            active_locks: state.input_locks.len(),
            prelock_intents: state.prelock.len(),
            active_intents: state.active.len(),
            pending_intents: state.prelock.len().saturating_add(state.active.len()),
            terminal_entries: state.terminal.len(),
            terminal_bytes: state.terminal_bytes,
            submit_total: state.submit_total,
            submit_rpc_total: state.submit_rpc_total,
            submit_p2p_total: state.submit_p2p_total,
            rejected_total: state.rejected_total,
            overload_reject_total: state.overload_reject_total,
            normal_conflict_reject_total: state.normal_conflict_reject_total,
            dropped_total: state.dropped_total,
            expired_total: state.expired_total,
            pull_miss_total: state.pull_miss_total,
            pull_fail_total: state.pull_fail_total,
            fast_arbiter_queue_len: state.fast_arbiter_queue_len,
            fast_arbiter_wait_ms: latest.arbiter_wait_p95_ms,
            fast_arbiter_hold_ms: latest.arbiter_hold_p95_ms,
            basechain_block_latency_ms: latest.basechain_block_latency_ms,
            basechain_latency_delta_vs_baseline_ms: latest.basechain_latency_delta_vs_baseline_ms,
            mode_transition_total: state.mode_transition_total,
            mode_transition_normal_to_degraded_total: state.mode_transition_normal_to_degraded_total,
            mode_transition_degraded_to_paused_total: state.mode_transition_degraded_to_paused_total,
            mode_transition_paused_to_degraded_total: state.mode_transition_paused_to_degraded_total,
            mode_transition_degraded_to_normal_total: state.mode_transition_degraded_to_normal_total,
            terminal_evictions_retention_total: state.terminal_evictions_retention_total,
            terminal_evictions_expired_total: state.terminal_evictions_expired_total,
            terminal_evictions_oldest_total: state.terminal_evictions_oldest_total,
            fast_arbiter_queue_ratio: latest.queue_ratio,
            fast_validation_queue_ratio: latest.validation_queue_ratio,
            fast_worker_cpu_ratio: latest.cpu_ratio,
            revalidation_backlog_seconds: latest.revalidation_backlog_seconds,
        }
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, HfaState> {
        self.state.lock().expect("hfa state lock poisoned")
    }

    fn submit_rejected(
        &self,
        intent_id: RpcHash,
        reason: &str,
        now_ms: u64,
        retention_until_ms: Option<u64>,
    ) -> SubmitFastIntentResponse {
        let mut state = self.lock_state();
        self.sweep(&mut state, now_ms);
        state.rejected_total = state.rejected_total.saturating_add(1);
        if reason == REASON_RAIL_OVERLOADED {
            state.overload_reject_total = state.overload_reject_total.saturating_add(1);
        }
        self.submit_rejected_with_state(&state, intent_id, reason, retention_until_ms)
    }

    fn submit_rejected_with_state(
        &self,
        state: &HfaState,
        intent_id: RpcHash,
        reason: &str,
        retention_until_ms: Option<u64>,
    ) -> SubmitFastIntentResponse {
        SubmitFastIntentResponse {
            intent_id,
            status: RpcFastIntentStatus::Rejected,
            reason: Some(reason.to_string()),
            base_tx_id: None,
            node_epoch: state.node_epoch,
            expires_at_ms: None,
            retention_until_ms,
            cancel_token: None,
            basechain_submitted: false,
        }
    }

    fn snapshot_submit(&self, record: IntentRecord) -> SubmitFastIntentResponse {
        let base_tx_id = derive_base_tx_id_from_record(&record);
        SubmitFastIntentResponse {
            intent_id: record.intent_id,
            status: record.status,
            reason: record.reason,
            base_tx_id,
            node_epoch: record.node_epoch,
            expires_at_ms: record.expires_at_ms,
            retention_until_ms: record.retention_until_ms,
            cancel_token: record.cancel_token,
            basechain_submitted: false,
        }
    }

    fn reject_from_prelock(&self, state: &mut HfaState, intent_id: RpcHash, reason: &str, now_ms: u64) -> SubmitFastIntentResponse {
        let record = if let Some(mut pre) = state.prelock.remove(&intent_id) {
            pre.status = RpcFastIntentStatus::Rejected;
            pre.reason = Some(reason.to_string());
            pre.expires_at_ms = None;
            pre.confirm_after_ms = None;
            pre.retention_until_ms = Some(now_ms.saturating_add(self.config.terminal_retention_ms));
            pre.terminal_entered_at_ms = Some(now_ms);
            pre.cancel_token = None;
            pre
        } else {
            IntentRecord {
                intent_id,
                status: RpcFastIntentStatus::Rejected,
                reason: Some(reason.to_string()),
                node_epoch: state.node_epoch,
                base_tx: None,
                intent_nonce: 0,
                client_created_at_ms: now_ms,
                max_fee: 0,
                expires_at_ms: None,
                confirm_after_ms: None,
                retention_until_ms: Some(now_ms.saturating_add(self.config.terminal_retention_ms)),
                terminal_entered_at_ms: Some(now_ms),
                cancel_token: None,
                base_tx_fingerprint: RpcHash::from_bytes([0u8; 32]),
                inputs: Vec::new(),
                estimated_bytes: estimate_record_bytes(None),
                p2p_relayed: false,
            }
        };

        if reason == REASON_RAIL_OVERLOADED {
            state.overload_reject_total = state.overload_reject_total.saturating_add(1);
        }
        state.rejected_total = state.rejected_total.saturating_add(1);
        state.seen_cache.insert(intent_id, now_ms.saturating_add(self.config.seen_cache_ttl_ms));
        self.insert_terminal(state, record.clone(), now_ms);
        self.submit_rejected_with_state(state, intent_id, reason, record.retention_until_ms)
    }

    fn transition_active_to_terminal(
        &self,
        state: &mut HfaState,
        intent_id: RpcHash,
        status: RpcFastIntentStatus,
        reason: Option<String>,
        now_ms: u64,
    ) -> IntentRecord {
        let mut active = state.active.remove(&intent_id).expect("active intent must exist");
        for input in &active.inputs {
            state.input_locks.remove(input);
        }
        state.active_fingerprint.remove(&active.base_tx_fingerprint);
        active.status = status;
        active.reason = reason;
        active.expires_at_ms = None;
        active.confirm_after_ms = None;
        active.cancel_token = None;
        active.retention_until_ms = Some(now_ms.saturating_add(self.config.terminal_retention_ms));
        active.terminal_entered_at_ms = Some(now_ms);
        match status {
            RpcFastIntentStatus::Dropped => state.dropped_total = state.dropped_total.saturating_add(1),
            RpcFastIntentStatus::Expired => state.expired_total = state.expired_total.saturating_add(1),
            _ => {}
        }
        self.insert_terminal(state, active.clone(), now_ms);
        active
    }

    fn insert_terminal(&self, state: &mut HfaState, record: IntentRecord, now_ms: u64) {
        if let Some(existing) = state.terminal.insert(record.intent_id, record.clone()) {
            state.terminal_bytes = state.terminal_bytes.saturating_sub(existing.estimated_bytes);
        }
        state.terminal_bytes = state.terminal_bytes.saturating_add(record.estimated_bytes);
        self.evict_terminal(state, now_ms);
    }

    fn sweep(&self, state: &mut HfaState, now_ms: u64) {
        self.sync_fast_arbiter_queue_len(state);
        self.confirm_ready_active(state, now_ms);
        self.expire_active(state, now_ms);
        self.evict_seen_cache(state, now_ms);
        self.evict_fast_tx_routes(state, now_ms);
        self.evict_remote_hints(state, now_ms);
        self.evict_arbiter_samples(state, now_ms);
        self.evict_terminal(state, now_ms);
    }

    fn confirm_ready_active(&self, state: &mut HfaState, now_ms: u64) {
        if state.mode == HfaMode::Paused {
            return;
        }
        let ready_to_confirm: Vec<RpcHash> = state
            .active
            .iter()
            .filter_map(|(intent_id, record)| {
                (record.status == RpcFastIntentStatus::Locked)
                    .then_some(record.confirm_after_ms)
                    .flatten()
                    .and_then(|confirm_after_ms| (confirm_after_ms <= now_ms).then_some(*intent_id))
            })
            .collect();

        for intent_id in ready_to_confirm {
            if let Some(active) = state.active.get_mut(&intent_id) {
                active.status = RpcFastIntentStatus::FastConfirmed;
                active.confirm_after_ms = None;
            }
            state.outbound_microblocks.push(FastMicroblockP2pData { microblock_time_ms: now_ms, intent_ids: vec![intent_id] });
        }
    }

    fn expire_active(&self, state: &mut HfaState, now_ms: u64) {
        let expired: Vec<RpcHash> = state
            .active
            .iter()
            .filter_map(|(intent_id, record)| record.expires_at_ms.and_then(|expires_at| (expires_at <= now_ms).then_some(*intent_id)))
            .collect();

        for intent_id in expired {
            let _ = self.transition_active_to_terminal(
                state,
                intent_id,
                RpcFastIntentStatus::Expired,
                Some(REASON_TTL_EXPIRED.to_string()),
                now_ms,
            );
        }
    }

    fn evict_seen_cache(&self, state: &mut HfaState, now_ms: u64) {
        state.seen_cache.retain(|_, until| *until > now_ms);
    }

    fn evict_fast_tx_routes(&self, state: &mut HfaState, now_ms: u64) {
        state.fast_tx_routes.retain(|_, until| *until > now_ms);
    }

    fn evict_remote_hints(&self, state: &mut HfaState, now_ms: u64) {
        state.remote_microblock_hints.retain(|_, until| *until > now_ms);
    }

    fn finish_fast_arbiter_section(&self, state: &mut HfaState, now_ms: u64, wait_ms: u64, hold_ms: u64) {
        self.sync_fast_arbiter_queue_len(state);
        state.fast_arbiter_wait_samples_ms.push_back((now_ms, wait_ms));
        state.fast_arbiter_hold_samples_ms.push_back((now_ms, hold_ms));
        self.evict_arbiter_samples(state, now_ms);
    }

    fn sync_fast_arbiter_queue_len(&self, state: &mut HfaState) {
        state.fast_arbiter_queue_len = self.fast_arbiter_inflight.load(Ordering::Relaxed);
    }

    fn evict_arbiter_samples(&self, state: &mut HfaState, now_ms: u64) {
        while state
            .fast_arbiter_wait_samples_ms
            .front()
            .is_some_and(|(ts_ms, _)| ts_ms.saturating_add(ARBITER_SAMPLE_WINDOW_MS) < now_ms)
        {
            state.fast_arbiter_wait_samples_ms.pop_front();
        }
        while state
            .fast_arbiter_hold_samples_ms
            .front()
            .is_some_and(|(ts_ms, _)| ts_ms.saturating_add(ARBITER_SAMPLE_WINDOW_MS) < now_ms)
        {
            state.fast_arbiter_hold_samples_ms.pop_front();
        }
    }

    fn evict_terminal(&self, state: &mut HfaState, now_ms: u64) {
        let mut ids_to_evict: Vec<RpcHash> = Vec::new();
        let mut cause_by_id: HashMap<RpcHash, &'static str> = HashMap::new();
        for (id, record) in &state.terminal {
            if record.retention_until_ms.is_some_and(|until| until <= now_ms) {
                ids_to_evict.push(*id);
                cause_by_id.insert(*id, "retention");
            }
        }

        ids_to_evict.sort_unstable();
        ids_to_evict.dedup();

        let mut projected_len = state.terminal.len();
        let mut projected_bytes = state.terminal_bytes;
        for id in &ids_to_evict {
            if let Some(record) = state.terminal.get(id) {
                projected_len = projected_len.saturating_sub(1);
                projected_bytes = projected_bytes.saturating_sub(record.estimated_bytes);
            }
        }

        if projected_len > self.config.max_terminal_entries || projected_bytes > self.config.max_terminal_bytes {
            let mut expired_terminal_candidates: Vec<(RpcHash, u64)> = state
                .terminal
                .iter()
                .filter_map(|(id, record)| {
                    (!ids_to_evict.contains(id) && record.status == RpcFastIntentStatus::Expired)
                        .then_some((*id, record.terminal_entered_at_ms.unwrap_or(0)))
                })
                .collect();
            expired_terminal_candidates.sort_by_key(|(_, entered_at_ms)| *entered_at_ms);

            for (id, _) in expired_terminal_candidates {
                if projected_len <= self.config.max_terminal_entries && projected_bytes <= self.config.max_terminal_bytes {
                    break;
                }
                ids_to_evict.push(id);
                cause_by_id.entry(id).or_insert("expired");
                if let Some(record) = state.terminal.get(&id) {
                    projected_len = projected_len.saturating_sub(1);
                    projected_bytes = projected_bytes.saturating_sub(record.estimated_bytes);
                }
            }
        }

        if projected_len > self.config.max_terminal_entries || projected_bytes > self.config.max_terminal_bytes {
            let mut oldest_terminal_candidates: Vec<(RpcHash, u64)> = state
                .terminal
                .iter()
                .filter_map(|(id, record)| (!ids_to_evict.contains(id)).then_some((*id, record.terminal_entered_at_ms.unwrap_or(0))))
                .collect();
            oldest_terminal_candidates.sort_by_key(|(_, entered_at_ms)| *entered_at_ms);

            for (id, _) in oldest_terminal_candidates {
                if projected_len <= self.config.max_terminal_entries && projected_bytes <= self.config.max_terminal_bytes {
                    break;
                }
                ids_to_evict.push(id);
                cause_by_id.entry(id).or_insert("oldest");
                if let Some(record) = state.terminal.get(&id) {
                    projected_len = projected_len.saturating_sub(1);
                    projected_bytes = projected_bytes.saturating_sub(record.estimated_bytes);
                }
            }
        }

        ids_to_evict.sort_unstable();
        ids_to_evict.dedup();
        for id in ids_to_evict {
            if let Some(record) = state.terminal.remove(&id) {
                state.terminal_bytes = state.terminal_bytes.saturating_sub(record.estimated_bytes);
                match cause_by_id.get(&id).copied() {
                    Some("retention") => {
                        state.terminal_evictions_retention_total = state.terminal_evictions_retention_total.saturating_add(1)
                    }
                    Some("expired") => {
                        state.terminal_evictions_expired_total = state.terminal_evictions_expired_total.saturating_add(1)
                    }
                    Some("oldest") => state.terminal_evictions_oldest_total = state.terminal_evictions_oldest_total.saturating_add(1),
                    _ => {}
                }
            }
        }
    }

    fn update_mode(&self, state: &mut HfaState, cpu_ratio: f64, is_synced: bool, basechain_block_latency_ms: f64, now_ms: u64) {
        if state.last_mode_eval_ms != 0 && now_ms < state.last_mode_eval_ms.saturating_add(1_000) {
            return;
        }
        state.last_mode_eval_ms = now_ms;

        let queue_ratio = if self.config.fast_arbiter_queue_capacity == 0 {
            1.0
        } else {
            state.fast_arbiter_queue_len as f64 / self.config.fast_arbiter_queue_capacity as f64
        };
        let validation_queue_ratio = if self.config.max_pending_intents == 0 {
            1.0
        } else {
            state.prelock.len() as f64 / self.config.max_pending_intents as f64
        };
        self.evict_arbiter_samples(state, now_ms);
        let arbiter_wait_p95_ms = sample_p95(&state.fast_arbiter_wait_samples_ms);
        let arbiter_hold_p95_ms = sample_p95(&state.fast_arbiter_hold_samples_ms);
        state.latest_fast_arbiter_wait_ms_p95 = arbiter_wait_p95_ms;
        state.latest_fast_arbiter_hold_ms_p95 = arbiter_hold_p95_ms;

        let latency_ms = basechain_block_latency_ms.max(0.0);
        if state.basechain_latency_baseline_ms <= 0.0 {
            state.basechain_latency_baseline_ms = latency_ms.max(1.0);
        } else {
            // Keep a slow-moving baseline to detect sustained regressions while avoiding spurious spikes.
            state.basechain_latency_baseline_ms = state.basechain_latency_baseline_ms * 0.99 + latency_ms * 0.01;
        }
        let basechain_latency_delta_vs_baseline_ms = (latency_ms - state.basechain_latency_baseline_ms).max(0.0);
        let basechain_latency_delta_ratio = basechain_latency_delta_vs_baseline_ms / state.basechain_latency_baseline_ms.max(1.0);
        state.basechain_block_latency_ms = latency_ms;
        state.basechain_latency_delta_vs_baseline_ms = basechain_latency_delta_vs_baseline_ms;
        state.basechain_latency_delta_ratio = basechain_latency_delta_ratio;

        let revalidation_budget_per_second = self.revalidation_budget_for_mode(state.mode).max(1) as f64;
        let revalidation_backlog_seconds = state.active.len() as f64 / revalidation_budget_per_second;

        state.mode_samples.push_back(ModeSample {
            ts_ms: now_ms,
            submit_total: state.submit_total,
            overload_reject_total: state.overload_reject_total,
            pull_fail_total: state.pull_fail_total,
            queue_ratio,
            validation_queue_ratio,
            arbiter_wait_p95_ms,
            arbiter_hold_p95_ms,
            cpu_ratio,
            revalidation_backlog_seconds,
            basechain_latency_delta_ratio,
            basechain_block_latency_ms: latency_ms,
            basechain_latency_delta_vs_baseline_ms,
        });
        while state.mode_samples.front().is_some_and(|sample| sample.ts_ms.saturating_add(MODE_SAMPLE_WINDOW_MS) < now_ms) {
            state.mode_samples.pop_front();
        }

        let oldest = state.mode_samples.front().copied().unwrap_or(ModeSample {
            ts_ms: now_ms,
            submit_total: state.submit_total,
            overload_reject_total: state.overload_reject_total,
            pull_fail_total: state.pull_fail_total,
            queue_ratio,
            validation_queue_ratio,
            arbiter_wait_p95_ms,
            arbiter_hold_p95_ms,
            cpu_ratio,
            revalidation_backlog_seconds,
            basechain_latency_delta_ratio,
            basechain_block_latency_ms: latency_ms,
            basechain_latency_delta_vs_baseline_ms,
        });
        let newest = state.mode_samples.back().copied().unwrap_or(oldest);
        let submit_delta = newest.submit_total.saturating_sub(oldest.submit_total).max(1);
        let overload_reject_rate_10s =
            newest.overload_reject_total.saturating_sub(oldest.overload_reject_total) as f64 / submit_delta as f64;
        let pull_fail_rate_10s = newest.pull_fail_total.saturating_sub(oldest.pull_fail_total) as f64 / submit_delta as f64;
        let basechain_latency_delta_p95_ratio =
            sample_p95_f64(state.mode_samples.iter().map(|sample| sample.basechain_latency_delta_ratio));

        let degrade_trigger = newest.queue_ratio >= 0.70
            || newest.validation_queue_ratio >= 0.80
            || newest.arbiter_wait_p95_ms >= 15.0
            || newest.cpu_ratio >= 0.75
            || overload_reject_rate_10s >= 0.03
            || pull_fail_rate_10s >= 0.10;
        let pause_trigger = newest.queue_ratio >= 0.90
            || newest.validation_queue_ratio >= 0.95
            || newest.arbiter_wait_p95_ms >= 40.0
            || newest.cpu_ratio >= 0.90
            || basechain_latency_delta_p95_ratio >= 0.10
            || newest.revalidation_backlog_seconds >= 5.0
            || !is_synced;

        state.degrade_trigger_streak = if degrade_trigger { state.degrade_trigger_streak.saturating_add(1) } else { 0 };
        state.pause_trigger_streak = if pause_trigger { state.pause_trigger_streak.saturating_add(1) } else { 0 };

        let low_water = newest.queue_ratio <= 0.40
            && newest.validation_queue_ratio <= 0.40
            && newest.arbiter_wait_p95_ms <= 8.0
            && newest.cpu_ratio <= self.config.cpu_low_water_ratio
            && overload_reject_rate_10s <= 0.002
            && pull_fail_rate_10s <= 0.02;
        state.pause_recovery_streak = if !pause_trigger && low_water { state.pause_recovery_streak.saturating_add(1) } else { 0 };
        state.normal_recovery_streak = if !degrade_trigger && low_water { state.normal_recovery_streak.saturating_add(1) } else { 0 };

        let previous_mode = state.mode;
        state.mode = match state.mode {
            HfaMode::Normal => {
                if state.degrade_trigger_streak >= 3 {
                    HfaMode::Degraded
                } else {
                    HfaMode::Normal
                }
            }
            HfaMode::Degraded => {
                if state.pause_trigger_streak >= 2 {
                    HfaMode::Paused
                } else if state.normal_recovery_streak >= 60 {
                    HfaMode::Normal
                } else {
                    HfaMode::Degraded
                }
            }
            HfaMode::Paused => {
                if state.pause_recovery_streak >= 30 {
                    HfaMode::Degraded
                } else {
                    HfaMode::Paused
                }
            }
        };

        if previous_mode != state.mode {
            state.mode_transition_total = state.mode_transition_total.saturating_add(1);
            match (previous_mode, state.mode) {
                (HfaMode::Normal, HfaMode::Degraded) => {
                    state.mode_transition_normal_to_degraded_total = state.mode_transition_normal_to_degraded_total.saturating_add(1)
                }
                (HfaMode::Degraded, HfaMode::Paused) => {
                    state.mode_transition_degraded_to_paused_total = state.mode_transition_degraded_to_paused_total.saturating_add(1)
                }
                (HfaMode::Paused, HfaMode::Degraded) => {
                    state.mode_transition_paused_to_degraded_total = state.mode_transition_paused_to_degraded_total.saturating_add(1)
                }
                (HfaMode::Degraded, HfaMode::Normal) => {
                    state.mode_transition_degraded_to_normal_total = state.mode_transition_degraded_to_normal_total.saturating_add(1)
                }
                _ => {}
            }
            warn!("HFA mode transition: {} -> {}", mode_name(previous_mode), mode_name(state.mode));
            if state.mode == HfaMode::Paused {
                state.paused_since_ms = Some(now_ms);
                state.paused_stuck_alerted = false;
            } else {
                state.paused_since_ms = None;
                state.paused_stuck_alerted = false;
            }
            state.degrade_trigger_streak = 0;
            state.pause_trigger_streak = 0;
            state.pause_recovery_streak = 0;
            state.normal_recovery_streak = 0;
        }

        if state.mode == HfaMode::Paused
            && state.paused_since_ms.is_some_and(|paused_since_ms| paused_since_ms.saturating_add(60_000) <= now_ms)
            && !state.paused_stuck_alerted
        {
            state.paused_stuck_alerted = true;
            warn!("HFA alert: fast rail has been in paused mode for at least 60 seconds");
        }
    }

    fn microblock_interval_ms_for_mode(&self, mode: HfaMode) -> u64 {
        match mode {
            HfaMode::Normal => self.config.microblock_interval_ms_normal,
            HfaMode::Degraded => self.config.microblock_interval_ms_degraded,
            HfaMode::Paused => self.config.microblock_interval_ms_degraded,
        }
    }

    fn revalidation_budget_for_mode(&self, mode: HfaMode) -> usize {
        match mode {
            HfaMode::Normal => self.config.revalidation_budget_normal,
            HfaMode::Degraded | HfaMode::Paused => self.config.revalidation_budget_degraded,
        }
    }
}

fn derive_intent_id(
    network_id: &str,
    base_tx_fingerprint: RpcHash,
    intent_nonce: u64,
    client_created_at_ms: u64,
    max_fee: u64,
) -> RpcHash {
    let mut hasher = TransactionHash::new();
    hasher.update(b"FAST_INTENT_V1");
    hasher.update(network_id.as_bytes());
    hasher.update(base_tx_fingerprint.as_bytes());
    hasher.update(intent_nonce.to_le_bytes());
    hasher.update(client_created_at_ms.to_le_bytes());
    hasher.update(max_fee.to_le_bytes());
    hasher.finalize()
}

fn derive_intent_id_from_rpc_tx(
    network_id: &str,
    base_tx: &RpcTransaction,
    intent_nonce: u64,
    client_created_at_ms: u64,
    max_fee: u64,
) -> RpcHash {
    let mut hasher = TransactionHash::new();
    hasher.update(b"FAST_INTENT_V1");
    hasher.update(network_id.as_bytes());
    hasher.update(base_tx.version.to_le_bytes());
    hasher.update(base_tx.lock_time.to_le_bytes());
    let subnetwork_bytes: &[u8] = base_tx.subnetwork_id.as_ref();
    hasher.update(subnetwork_bytes);
    hasher.update(base_tx.gas.to_le_bytes());
    hasher.update((base_tx.payload.len() as u64).to_le_bytes());
    hasher.update(base_tx.payload.as_slice());
    hasher.update((base_tx.inputs.len() as u64).to_le_bytes());
    for input in &base_tx.inputs {
        hasher.update(input.previous_outpoint.transaction_id.as_bytes());
        hasher.update(input.previous_outpoint.index.to_le_bytes());
        hasher.update((input.signature_script.len() as u64).to_le_bytes());
        hasher.update(input.signature_script.as_slice());
        hasher.update(input.sequence.to_le_bytes());
        hasher.update(input.sig_op_count.to_le_bytes());
    }
    hasher.update((base_tx.outputs.len() as u64).to_le_bytes());
    for output in &base_tx.outputs {
        hasher.update(output.value.to_le_bytes());
        hasher.update(output.script_public_key.version.to_le_bytes());
        hasher.update((output.script_public_key.script().len() as u64).to_le_bytes());
        hasher.update(output.script_public_key.script());
    }
    hasher.update(intent_nonce.to_le_bytes());
    hasher.update(client_created_at_ms.to_le_bytes());
    hasher.update(max_fee.to_le_bytes());
    hasher.finalize()
}

fn build_cancel_token(intent_id: RpcHash, node_epoch: u64, now_ms: u64) -> String {
    let mut hasher = TransactionHash::new();
    hasher.update(b"HFA_CANCEL_TOKEN_V1");
    hasher.update(intent_id.as_bytes());
    hasher.update(node_epoch.to_le_bytes());
    hasher.update(now_ms.to_le_bytes());
    hasher.finalize().to_string()
}

fn map_tx_error_to_reason(err: TxRuleError) -> &'static str {
    match err {
        TxRuleError::MissingTxOutpoints => REASON_MISSING_INPUTS,
        TxRuleError::TooManyInputs(_, _)
        | TxRuleError::TooManyOutputs(_, _)
        | TxRuleError::TooBigSignatureScript(_, _)
        | TxRuleError::TooBigScriptPublicKey(_, _)
        | TxRuleError::UnknownTxVersion(_)
        | TxRuleError::SubnetworksDisabled(_)
        | TxRuleError::NonCoinbaseTxHasPayload
        | TxRuleError::PayloadInInvalidSubnetwork(_)
        | TxRuleError::PayloadSubnetworkHasNoPayload
        | TxRuleError::PayloadLengthAboveMax(_, _)
        | TxRuleError::TxHasGas => REASON_NONSTANDARD_BASE_TX,
        TxRuleError::FeerateTooLow => REASON_FEE_RATE_BELOW_FLOOR,
        _ => REASON_INVALID_BASE_TX,
    }
}

fn mode_name(mode: HfaMode) -> &'static str {
    match mode {
        HfaMode::Normal => "normal",
        HfaMode::Degraded => "degraded",
        HfaMode::Paused => "paused",
    }
}

fn sample_p95(samples: &VecDeque<(u64, u64)>) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let mut values: Vec<u64> = samples.iter().map(|(_, value)| *value).collect();
    values.sort_unstable();
    let index = ((values.len() as f64) * 0.95).ceil() as usize;
    values[index.saturating_sub(1).min(values.len().saturating_sub(1))] as f64
}

fn sample_p95_f64<I: Iterator<Item = f64>>(iter: I) -> f64 {
    let mut values: Vec<f64> = iter.filter(|value| value.is_finite()).collect();
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let index = ((values.len() as f64) * 0.95).ceil() as usize;
    values[index.saturating_sub(1).min(values.len().saturating_sub(1))]
}

fn estimate_record_bytes(base_tx: Option<&RpcTransaction>) -> usize {
    const BASE_OVERHEAD_BYTES: usize = 256;
    let Some(tx) = base_tx else {
        return BASE_OVERHEAD_BYTES;
    };

    let input_bytes: usize =
        tx.inputs.iter().map(|input| 32usize.saturating_add(8).saturating_add(input.signature_script.len()).saturating_add(16)).sum();
    let output_bytes: usize =
        tx.outputs.iter().map(|output| 8usize.saturating_add(output.script_public_key.script().len()).saturating_add(8)).sum();
    BASE_OVERHEAD_BYTES.saturating_add(input_bytes).saturating_add(output_bytes).saturating_add(tx.payload.len()).saturating_add(64)
}

fn derive_base_tx_id_from_record(record: &IntentRecord) -> Option<RpcHash> {
    record.base_tx.as_ref().and_then(|base_tx| {
        let tx: Transaction = base_tx.clone().try_into().ok()?;
        Some(tx.id())
    })
}

#[async_trait]
impl HfaP2pBridge for HfaEngine {
    fn hfa_enabled(&self) -> bool {
        self.config.enabled
    }

    fn has_fast_intent(&self, intent_id: RpcHash) -> bool {
        self.has_intent(intent_id)
    }

    fn has_fast_lock_conflict_for_tx(&self, tx: &Transaction) -> bool {
        HfaEngine::has_fast_lock_conflict_for_tx(self, tx)
    }

    fn get_fast_intents(&self, intent_ids: &[RpcHash]) -> Vec<FastIntentP2pData> {
        self.get_fast_intents_for_p2p(intent_ids)
    }

    async fn submit_remote_fast_intent(
        &self,
        network_id: &str,
        intent: FastIntentP2pData,
        session: ConsensusProxy,
        mining_manager: MiningManagerProxy,
        is_synced: bool,
        cpu_ratio: f64,
    ) {
        let request = SubmitFastIntentRequest {
            base_tx: (&intent.base_tx).into(),
            intent_nonce: intent.intent_nonce,
            client_created_at_ms: intent.client_created_at_ms,
            max_fee: intent.max_fee,
        };
        let sink_timestamp_ms = session.async_get_sink_timestamp().await;
        let basechain_block_latency_ms = unix_now().saturating_sub(sink_timestamp_ms) as f64;
        let response = self
            .submit_fast_intent(
                network_id,
                request,
                session.clone(),
                mining_manager.clone(),
                is_synced,
                cpu_ratio,
                basechain_block_latency_ms,
                FastIngressSource::P2p,
            )
            .await;

        let tx_id = intent.base_tx.id();
        if !matches!(response.status, RpcFastIntentStatus::Locked | RpcFastIntentStatus::FastConfirmed) {
            let reason = response.reason.as_deref().unwrap_or("");
            if matches!(reason, REASON_MISSING_INPUTS | REASON_CLOCK_DRIFT_EXCEEDED) {
                info!(
                    "Fastchain receive skipped: intent {} tx {} status={:?} reason={:?}",
                    response.intent_id, tx_id, response.status, response.reason
                );
            } else {
                warn!(
                    "Fastchain receive rejected: intent {} tx {} status={:?} reason={:?}",
                    response.intent_id, tx_id, response.status, response.reason
                );
            }
            return;
        }

        let insert_results = mining_manager
            .clone()
            .validate_and_insert_transaction_batch(&session, vec![intent.base_tx], Priority::Low, Orphan::Allowed, RbfPolicy::Allowed)
            .await;

        let accepted_in_mempool = insert_results.first().map(|result| result.is_ok()).unwrap_or(false);
        if accepted_in_mempool {
            self.mark_fast_tx_route(tx_id);
            info!("Fastchain receive accepted: intent {} tx {} added to mempool", response.intent_id, tx_id);
            return;
        }

        let tx_already_known = mining_manager.clone().has_transaction(tx_id, TransactionQuery::All).await
            || mining_manager.clone().has_accepted_transaction(tx_id).await;
        if tx_already_known {
            self.mark_fast_tx_route(tx_id);
            info!("Fastchain receive deduplicated: intent {} tx {} already known", response.intent_id, tx_id);
            return;
        }

        if let Some(cancel_token) = response.cancel_token {
            warn!(
                "Fastchain receive rejected: intent {} tx {} failed mempool insertion, cancelling local fast context",
                response.intent_id, tx_id
            );
            let _ = self.cancel_fast_intent(CancelFastIntentRequest {
                intent_id: response.intent_id,
                cancel_token,
                node_epoch: response.node_epoch,
            });
        }
    }

    fn on_remote_fast_microblock(&self, intent_ids: &[RpcHash], now_ms: u64) -> Vec<RpcHash> {
        HfaEngine::on_remote_fast_microblock(self, intent_ids, now_ms)
    }

    fn record_pull_fail(&self, count: u64) {
        HfaEngine::record_pull_fail(self, count);
    }

    fn take_outbound_fast_microblocks(&self) -> Vec<FastMicroblockP2pData> {
        HfaEngine::take_outbound_fast_microblocks(self)
    }
}

// @all - leave the tests in place until the next hard fork in case we still need them or problems arise.

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_hash(byte: u8) -> RpcHash {
        RpcHash::from_bytes([byte; 32])
    }

    fn dummy_record(intent_id: RpcHash, status: RpcFastIntentStatus, terminal_entered_at_ms: Option<u64>) -> IntentRecord {
        IntentRecord {
            intent_id,
            status,
            reason: None,
            node_epoch: 1,
            base_tx: None,
            intent_nonce: 1,
            client_created_at_ms: 1,
            max_fee: 1,
            expires_at_ms: None,
            confirm_after_ms: None,
            retention_until_ms: Some(10_000),
            terminal_entered_at_ms,
            cancel_token: None,
            base_tx_fingerprint: sample_hash(42),
            inputs: Vec::new(),
            estimated_bytes: 1,
            p2p_relayed: false,
        }
    }

    #[test]
    fn derive_intent_id_from_rpc_tx_ignores_mass() {
        let base_tx = RpcTransaction {
            version: 1,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
            subnetwork_id: Default::default(),
            gas: 0,
            payload: Vec::new(),
            mass: 1,
            fast_path: None,
            verbose_data: None,
        };
        let mut altered_mass_tx = base_tx.clone();
        altered_mass_tx.mass = 999_999;

        let id1 = derive_intent_id_from_rpc_tx("mainnet", &base_tx, 7, 100, 200);
        let id2 = derive_intent_id_from_rpc_tx("mainnet", &altered_mass_tx, 7, 100, 200);
        assert_eq!(id1, id2);
    }

    #[test]
    fn confirm_ready_active_moves_locked_to_fast_confirmed() {
        let engine = HfaEngine::new(HfaRuntimeConfig::new(true, 0.7));
        let intent_id = sample_hash(10);

        let mut state = HfaState::new(1);
        let mut record = dummy_record(intent_id, RpcFastIntentStatus::Locked, None);
        record.confirm_after_ms = Some(100);
        state.active.insert(intent_id, record);

        engine.confirm_ready_active(&mut state, 100);
        let active = state.active.get(&intent_id).unwrap();
        assert_eq!(active.status, RpcFastIntentStatus::FastConfirmed);
        assert!(active.confirm_after_ms.is_none());
        assert_eq!(state.outbound_microblocks.len(), 1);
        assert_eq!(state.outbound_microblocks[0].intent_ids, vec![intent_id]);
    }

    #[test]
    fn paused_mode_does_not_emit_microblocks() {
        let engine = HfaEngine::new(HfaRuntimeConfig::new(true, 0.7));
        let intent_id = sample_hash(12);

        let mut state = HfaState::new(1);
        state.mode = HfaMode::Paused;
        let mut record = dummy_record(intent_id, RpcFastIntentStatus::Locked, None);
        record.confirm_after_ms = Some(100);
        state.active.insert(intent_id, record);

        engine.confirm_ready_active(&mut state, 100);
        let active = state.active.get(&intent_id).unwrap();
        assert_eq!(active.status, RpcFastIntentStatus::Locked);
        assert!(state.outbound_microblocks.is_empty());
    }

    #[test]
    fn remote_microblock_marks_unknown_as_missing_and_hint() {
        let engine = HfaEngine::new(HfaRuntimeConfig::new(true, 0.7));
        let intent_id = sample_hash(11);
        let missing = engine.on_remote_fast_microblock(&[intent_id], 1000);
        assert_eq!(missing, vec![intent_id]);

        let state = engine.lock_state();
        assert!(state.remote_microblock_hints.contains_key(&intent_id));
    }

    #[test]
    fn retention_eviction_prefers_expired_terminal_entries() {
        let mut config = HfaRuntimeConfig::new(true, 0.7);
        config.max_terminal_entries = 1;
        let engine = HfaEngine::new(config);
        let mut state = HfaState::new(1);

        let expired_id = sample_hash(1);
        let other_id = sample_hash(2);
        let expired = dummy_record(expired_id, RpcFastIntentStatus::Expired, Some(100));
        let other = dummy_record(other_id, RpcFastIntentStatus::Cancelled, Some(200));
        state.terminal.insert(expired_id, expired);
        state.terminal.insert(other_id, other);
        state.terminal_bytes = 2;

        engine.evict_terminal(&mut state, 0);
        assert!(!state.terminal.contains_key(&expired_id));
        assert!(state.terminal.contains_key(&other_id));
    }

    #[test]
    fn has_fast_lock_conflict_for_inputs_reports_true() {
        let engine = HfaEngine::new(HfaRuntimeConfig::new(true, 0.7));
        let outpoint = TransactionOutpoint { transaction_id: sample_hash(21), index: 0 };
        {
            let mut state = engine.lock_state();
            state.input_locks.insert(outpoint, sample_hash(22));
        }

        assert!(engine.has_fast_lock_conflict_for_inputs(&[outpoint]));
        assert_eq!(engine.metrics_snapshot().normal_conflict_reject_total, 1);
    }

    #[test]
    fn dropped_transition_increments_counter() {
        let engine = HfaEngine::new(HfaRuntimeConfig::new(true, 0.7));
        let intent_id = sample_hash(30);
        let outpoint = TransactionOutpoint { transaction_id: sample_hash(31), index: 1 };

        let mut state = HfaState::new(1);
        let mut record = dummy_record(intent_id, RpcFastIntentStatus::Locked, None);
        record.inputs = vec![outpoint];
        record.base_tx_fingerprint = sample_hash(32);
        state.active_fingerprint.insert(record.base_tx_fingerprint, intent_id);
        state.input_locks.insert(outpoint, intent_id);
        state.active.insert(intent_id, record);

        let _ = engine.transition_active_to_terminal(
            &mut state,
            intent_id,
            RpcFastIntentStatus::Dropped,
            Some(REASON_INVALIDATED_BY_CHAIN_UPDATE.to_string()),
            100,
        );
        assert_eq!(state.dropped_total, 1);
        assert!(!state.active.contains_key(&intent_id));
        assert!(state.terminal.contains_key(&intent_id));
    }

    #[test]
    fn same_base_tx_does_not_trigger_fast_lock_conflict() {
        let engine = HfaEngine::new(HfaRuntimeConfig::new(true, 0.7));
        let intent_id = sample_hash(40);
        let outpoint = TransactionOutpoint::new(sample_hash(41), 0);
        let tx = Transaction::new(
            1,
            vec![cryptix_consensus_core::tx::TransactionInput::new(outpoint, vec![0x51], 0, 0)],
            Vec::new(),
            0,
            Default::default(),
            0,
            vec![1],
        );
        let tx_fingerprint = hash_tx(&tx, false);
        {
            let mut state = engine.lock_state();
            state.active_fingerprint.insert(tx_fingerprint, intent_id);
            state.input_locks.insert(outpoint, intent_id);
        }

        assert!(!engine.has_fast_lock_conflict_for_tx(&tx));
    }

    #[test]
    fn competing_tx_with_same_inputs_triggers_fast_lock_conflict() {
        let engine = HfaEngine::new(HfaRuntimeConfig::new(true, 0.7));
        let intent_id = sample_hash(50);
        let outpoint = TransactionOutpoint::new(sample_hash(51), 0);
        let locked_tx = Transaction::new(
            1,
            vec![cryptix_consensus_core::tx::TransactionInput::new(outpoint, vec![0x51], 0, 0)],
            Vec::new(),
            0,
            Default::default(),
            0,
            vec![1],
        );
        let competing_tx = Transaction::new(
            1,
            vec![cryptix_consensus_core::tx::TransactionInput::new(outpoint, vec![0x51], 0, 0)],
            Vec::new(),
            0,
            Default::default(),
            0,
            vec![2],
        );
        let locked_fingerprint = hash_tx(&locked_tx, false);
        {
            let mut state = engine.lock_state();
            state.active_fingerprint.insert(locked_fingerprint, intent_id);
            state.input_locks.insert(outpoint, intent_id);
        }

        assert!(engine.has_fast_lock_conflict_for_tx(&competing_tx));
    }

    #[test]
    fn sample_p95_returns_expected_value() {
        let mut samples = VecDeque::new();
        for v in [1u64, 2, 3, 4, 5, 100] {
            samples.push_back((1, v));
        }
        assert_eq!(sample_p95(&samples), 100.0);
    }

    #[test]
    fn estimate_record_bytes_increases_with_payload() {
        let mut tx = RpcTransaction {
            version: 1,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
            subnetwork_id: Default::default(),
            gas: 0,
            payload: Vec::new(),
            mass: 1,
            fast_path: None,
            verbose_data: None,
        };
        let base = estimate_record_bytes(Some(&tx));
        tx.payload = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let with_payload = estimate_record_bytes(Some(&tx));
        assert!(with_payload > base);
    }

    #[test]
    fn mode_transitions_to_degraded_on_arbiter_wait() {
        let engine = HfaEngine::new(HfaRuntimeConfig::new(true, 0.7));
        let mut state = HfaState::new(1);
        state.fast_arbiter_wait_samples_ms.push_back((1000, 20));
        engine.update_mode(&mut state, 0.2, true, 100.0, 1000);
        state.fast_arbiter_wait_samples_ms.push_back((2000, 20));
        engine.update_mode(&mut state, 0.2, true, 100.0, 2000);
        state.fast_arbiter_wait_samples_ms.push_back((3000, 20));
        engine.update_mode(&mut state, 0.2, true, 100.0, 3000);
        assert_eq!(state.mode, HfaMode::Degraded);
    }

    #[test]
    fn mode_transitions_to_paused_on_basechain_latency_delta() {
        let engine = HfaEngine::new(HfaRuntimeConfig::new(true, 0.7));
        let mut state = HfaState::new(1);
        state.mode = HfaMode::Degraded;
        state.basechain_latency_baseline_ms = 100.0;
        engine.update_mode(&mut state, 0.2, true, 120.0, 1000);
        engine.update_mode(&mut state, 0.2, true, 120.0, 2000);
        assert_eq!(state.mode, HfaMode::Paused);
    }
}
