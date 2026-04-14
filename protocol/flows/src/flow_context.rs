use crate::flowcontext::{
    orphans::{OrphanBlocksPool, OrphanOutput},
    process_queue::ProcessQueue,
    transactions::TransactionsSpread,
};
use crate::hfa::{FastIntentP2pData, FastMicroblockP2pData, HfaP2pBridge, HFA_P2P_SERVICE_BIT};
use crate::node_identity::{
    compute_node_id, create_ephemeral_identity, is_valid_pow_nonce, load_or_create_identity, network_code_from_name,
    sign_node_auth_proof, verify_node_auth_proof, UnifiedNodeIdentity,
};
use crate::pq_handshake::{
    compute_pq_handshake_proof, decapsulate_mlkem1024, encapsulate_mlkem1024, generate_mlkem1024_keypair, PQ_HANDSHAKE_PROOF_SIZE,
    PQ_MLKEM1024_CIPHERTEXT_SIZE, PQ_MLKEM1024_PUBLIC_KEY_SIZE,
};
use crate::strong_node_claims::{
    ClaimIngestOutcome, StrongNodeClaimsEngine, StrongNodeClaimsRuntimeSnapshot, STRONG_NODE_CLAIMS_P2P_SERVICE_BIT,
};
use crate::{v5, v6};
use async_trait::async_trait;
use cryptix_addressmanager::AddressManager;
use cryptix_connectionmanager::{AntiFraudMode, ConnectionManager};
use cryptix_consensus_core::api::{BlockValidationFuture, BlockValidationFutures};
use cryptix_consensus_core::block::Block;
use cryptix_consensus_core::config::Config;
use cryptix_consensus_core::errors::block::RuleError;
use cryptix_consensus_core::tx::{Transaction, TransactionId};
use cryptix_consensus_core::ChainPath;
use cryptix_consensus_notify::{
    notification::{Notification, PruningPointUtxoSetOverrideNotification},
    root::ConsensusNotificationRoot,
};
use cryptix_consensusmanager::{BlockProcessingBatch, ConsensusInstance, ConsensusManager, ConsensusProxy};
use cryptix_core::{
    cryptixd_env::{name, version},
    debug, info,
    task::tick::TickService,
};
use cryptix_core::{time::unix_now, warn};
use cryptix_hashes::Hash;
use cryptix_mining::mempool::tx::{Orphan, Priority};
use cryptix_mining::{manager::MiningManagerProxy, mempool::tx::RbfPolicy};
use cryptix_notify::notifier::Notify;
use cryptix_p2p_lib::{
    common::ProtocolError,
    convert::model::version::Version,
    make_message,
    pb::{
        cryptixd_message::Payload, BlockProducerClaimV1Message, CryptixdMessage, FastIntentMessage, FastMicroblockMessage,
        InvRelayBlockMessage,
    },
    ConnectionInitializer, CryptixdHandshake, Hub, PeerKey, PeerProperties, Router,
};
use cryptix_utils::iter::IterExtensions;
use cryptix_utils::networking::PeerId;
use futures::future::join_all;
use parking_lot::{Mutex, RwLock};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Instant;
use std::{collections::hash_map::Entry, fmt::Display};
use std::{
    iter::once,
    ops::Deref,
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::{
    mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    RwLock as AsyncRwLock,
};
use tokio_stream::{wrappers::UnboundedReceiverStream, StreamExt};
use uuid::Uuid;

/// The P2P protocol version. Currently the only one supported.
const PROTOCOL_VERSION: u32 = 8;
const PRE_HARD_FORK_PROTOCOL_VERSION: u32 = 7;
const LEGACY_PROTOCOL_VERSION: u32 = 6;
const MIN_PRE_HARD_FORK_PROTOCOL_VERSION: u32 = 5;
const QUANTUM_HANDSHAKE_STATE_UNKNOWN: u8 = 0;
const QUANTUM_HANDSHAKE_STATE_LEGACY: u8 = 1;
const QUANTUM_HANDSHAKE_STATE_ENFORCED: u8 = 2;

/// See `check_orphan_resolution_range`
const BASELINE_ORPHAN_RESOLUTION_RANGE: u32 = 5;

/// Orphans are kept as full blocks so we cannot hold too much of them in memory
const MAX_ORPHANS_UPPER_BOUND: usize = 1024;

/// The min time to wait before allowing another parallel request
const REQUEST_SCOPE_WAIT_TIME: Duration = Duration::from_secs(1);

/// How many misbehavior strikes are required before banning a peer.
const MISBEHAVIOR_BAN_SCORE: u32 = 5;

/// Every full interval without additional misbehavior reduces the strike score by one.
const MISBEHAVIOR_DECAY_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// Forget stale peer scores to keep the tracker bounded over time.
const MISBEHAVIOR_FORGET_AFTER: Duration = Duration::from_secs(60 * 60);

/// Soft memory cap for tracked peers in the misbehavior map.
const MISBEHAVIOR_MAX_TRACKED_PEERS: usize = 4096;

/// Soft inbound connection rate-limit window and threshold per IP.
const INBOUND_CONNECTION_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const INBOUND_CONNECTION_RATE_LIMIT_MAX_ATTEMPTS: usize = 20;
const STRONG_NODES_TICK_INTERVAL: Duration = Duration::from_secs(30);
const STRONG_NODE_CLAIMS_GOSSIP_FANOUT: usize = 8;

/// Maximum frequency in which rate-limit breaches can add strikes.
const INBOUND_CONNECTION_RATE_LIMIT_STRIKE_COOLDOWN: Duration = Duration::from_secs(60);

/// Soft memory cap for tracked peer IPs in the inbound connection limiter map.
const INBOUND_CONNECTION_RATE_LIMIT_MAX_TRACKED_IPS: usize = 4096;

fn anti_fraud_hash_window_from_vec(entries: &[[u8; 32]]) -> Option<[[u8; 32]; 3]> {
    if entries.len() != 3 {
        return None;
    }
    Some([entries[0], entries[1], entries[2]])
}

fn short_hex_for_log(data: &[u8]) -> String {
    if data.is_empty() {
        return "<empty>".to_string();
    }
    if data.len() <= 8 {
        return hex::encode(data);
    }
    format!("{}...{}", hex::encode(&data[..4]), hex::encode(&data[data.len() - 4..]))
}

fn is_compatible_peer_network(local_network: &str, remote_network: &str) -> bool {
    local_network == remote_network
}

/// Represents a block event to be logged
#[derive(Debug, PartialEq)]
pub enum BlockLogEvent {
    /// Accepted block via *relay*
    Relay(Hash),
    /// Accepted block via *submit block*
    Submit(Hash),
    /// Orphaned block with x missing roots
    Orphaned(Hash, usize),
    /// Unorphaned x blocks with hash being a representative
    Unorphaned(Hash, usize),
}

pub struct BlockEventLogger {
    bps: usize,
    sender: UnboundedSender<BlockLogEvent>,
    receiver: Mutex<Option<UnboundedReceiver<BlockLogEvent>>>,
}

impl BlockEventLogger {
    pub fn new(bps: usize) -> Self {
        let (sender, receiver) = unbounded_channel();
        Self { bps, sender, receiver: Mutex::new(Some(receiver)) }
    }

    pub fn log(&self, event: BlockLogEvent) {
        self.sender.send(event).unwrap();
    }

    /// Start the logger listener. Must be called from an async tokio context
    fn start(&self) {
        let chunk_limit = self.bps * 10; // We prefer that the 1 sec timeout forces the log, but nonetheless still want a reasonable bound on each chunk
        let receiver = self.receiver.lock().take().expect("expected to be called once");
        tokio::spawn(async move {
            let chunk_stream = UnboundedReceiverStream::new(receiver).chunks_timeout(chunk_limit, Duration::from_secs(1));
            tokio::pin!(chunk_stream);
            while let Some(chunk) = chunk_stream.next().await {
                #[derive(Default)]
                struct LogSummary {
                    // Representatives
                    relay_rep: Option<Hash>,
                    submit_rep: Option<Hash>,
                    orphan_rep: Option<Hash>,
                    unorphan_rep: Option<Hash>,
                    // Counts
                    relay_count: usize,
                    submit_count: usize,
                    orphan_count: usize,
                    unorphan_count: usize,
                    orphan_roots_count: usize,
                }

                struct LogHash {
                    op: Option<Hash>,
                }

                impl From<Option<Hash>> for LogHash {
                    fn from(op: Option<Hash>) -> Self {
                        Self { op }
                    }
                }

                impl Display for LogHash {
                    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        if let Some(hash) = self.op {
                            hash.fmt(f)
                        } else {
                            Ok(())
                        }
                    }
                }

                impl LogSummary {
                    fn relay(&self) -> LogHash {
                        self.relay_rep.into()
                    }

                    fn submit(&self) -> LogHash {
                        self.submit_rep.into()
                    }

                    fn orphan(&self) -> LogHash {
                        self.orphan_rep.into()
                    }

                    fn unorphan(&self) -> LogHash {
                        self.unorphan_rep.into()
                    }
                }

                let summary = chunk.into_iter().fold(LogSummary::default(), |mut summary, ev| {
                    match ev {
                        BlockLogEvent::Relay(hash) => {
                            summary.relay_count += 1;
                            summary.relay_rep = Some(hash)
                        }
                        BlockLogEvent::Submit(hash) => {
                            summary.submit_count += 1;
                            summary.submit_rep = Some(hash)
                        }
                        BlockLogEvent::Orphaned(hash, roots_count) => {
                            summary.orphan_roots_count += roots_count;
                            summary.orphan_count += 1;
                            summary.orphan_rep = Some(hash)
                        }
                        BlockLogEvent::Unorphaned(hash, count) => {
                            summary.unorphan_count += count;
                            summary.unorphan_rep = Some(hash)
                        }
                    }
                    summary
                });

                match (summary.submit_count, summary.relay_count) {
                    (0, 0) => {}
                    (1, 0) => info!("Accepted block {} via submit block", summary.submit()),
                    (n, 0) => info!("Accepted {} blocks ...{} via submit block", n, summary.submit()),
                    (0, 1) => info!("Accepted block {} via relay", summary.relay()),
                    (0, m) => info!("Accepted {} blocks ...{} via relay", m, summary.relay()),
                    (n, m) => {
                        info!("Accepted {} blocks ...{}, {} via relay and {} via submit block", n + m, summary.submit(), m, n)
                    }
                }

                match (summary.orphan_count, summary.orphan_roots_count) {
                    (0, 0) => {}
                    (n, m) => info!("Orphaned {} block(s) ...{} and queued {} missing roots", n, summary.orphan(), m),
                }

                match summary.unorphan_count {
                    0 => {}
                    1 => info!("Unorphaned block {}", summary.unorphan()),
                    n => info!("Unorphaned {} block(s) ...{}", n, summary.unorphan()),
                }
            }
        });
    }
}

pub struct FlowContextInner {
    pub node_id: PeerId,
    pub unified_node_identity: Arc<UnifiedNodeIdentity>,
    pub consensus_manager: Arc<ConsensusManager>,
    pub config: Arc<Config>,
    hub: Hub,
    orphans_pool: AsyncRwLock<OrphanBlocksPool>,
    shared_block_requests: Arc<Mutex<HashMap<Hash, RequestScopeMetadata>>>,
    transactions_spread: AsyncRwLock<TransactionsSpread>,
    shared_transaction_requests: Arc<Mutex<HashMap<TransactionId, RequestScopeMetadata>>>,
    is_ibd_running: Arc<AtomicBool>,
    ibd_metadata: Arc<RwLock<Option<IbdMetadata>>>,
    pub address_manager: Arc<Mutex<AddressManager>>,
    connection_manager: RwLock<Option<Arc<ConnectionManager>>>,
    autoban_enabled: bool,
    misbehaving_peer_scores: Mutex<HashMap<MisbehaviorIdentity, MisbehaviorRecord>>,
    inbound_connection_rate_limit: Mutex<HashMap<IpAddr, InboundConnectionRateLimitRecord>>,
    hfa_bridge: RwLock<Option<Arc<dyn HfaP2pBridge>>>,
    strong_node_claims_engine: Arc<StrongNodeClaimsEngine>,
    mining_manager: MiningManagerProxy,
    pub(crate) tick_service: Arc<TickService>,
    notification_root: Arc<ConsensusNotificationRoot>,
    quantum_handshake_mode_state: AtomicU8,
    quantum_handshake_start_logged: AtomicBool,
    quantum_handshake_key_sample_logged: AtomicBool,

    // Special sampling logger used only for high-bps networks where logs must be throttled
    block_event_logger: Option<BlockEventLogger>,

    // Orphan parameters
    orphan_resolution_range: u32,
    max_orphans: usize,
}

#[derive(Clone)]
pub struct FlowContext {
    inner: Arc<FlowContextInner>,
}

pub struct IbdRunningGuard {
    indicator: Arc<AtomicBool>,
}

impl Drop for IbdRunningGuard {
    fn drop(&mut self) {
        let result = self.indicator.compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst);
        assert!(result.is_ok())
    }
}

#[derive(Debug, Clone, Copy)]
struct IbdMetadata {
    /// The peer from which current IBD is syncing from
    peer: PeerKey,
    /// The DAA score of the relay block which triggered the current IBD
    daa_score: u64,
}

#[derive(Debug, Clone, Copy)]
struct MisbehaviorRecord {
    score: u32,
    last_seen: Instant,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
enum MisbehaviorIdentity {
    Ip(IpAddr),
    UnifiedNodeId([u8; 32]),
}

#[derive(Debug, Clone)]
struct InboundConnectionRateLimitRecord {
    attempts: VecDeque<Instant>,
    last_penalty: Option<Instant>,
    last_seen: Instant,
}

#[derive(Debug, Clone, Copy)]
struct InboundConnectionRateLimitVerdict {
    allowed: bool,
    attempts_in_window: usize,
    should_penalize: bool,
}

pub struct RequestScopeMetadata {
    pub timestamp: Instant,
    pub obtained: bool,
}

pub struct RequestScope<T: PartialEq + Eq + std::hash::Hash> {
    set: Arc<Mutex<HashMap<T, RequestScopeMetadata>>>,
    pub req: T,
}

impl<T: PartialEq + Eq + std::hash::Hash> RequestScope<T> {
    pub fn new(set: Arc<Mutex<HashMap<T, RequestScopeMetadata>>>, req: T) -> Self {
        Self { set, req }
    }

    /// Scope holders should use this function to report that the request has
    /// successfully been obtained from the peer and is now being processed
    pub fn report_obtained(&self) {
        if let Some(e) = self.set.lock().get_mut(&self.req) {
            e.obtained = true;
        }
    }
}

impl<T: PartialEq + Eq + std::hash::Hash> Drop for RequestScope<T> {
    fn drop(&mut self) {
        self.set.lock().remove(&self.req);
    }
}

impl Deref for FlowContext {
    type Target = FlowContextInner;

    fn deref(&self) -> &Self::Target {
        self.inner.as_ref()
    }
}

impl FlowContext {
    pub fn new(
        consensus_manager: Arc<ConsensusManager>,
        address_manager: Arc<Mutex<AddressManager>>,
        config: Arc<Config>,
        mining_manager: MiningManagerProxy,
        tick_service: Arc<TickService>,
        notification_root: Arc<ConsensusNotificationRoot>,
        autoban_enabled: bool,
        app_data_dir: PathBuf,
    ) -> Self {
        let hub = Hub::new();
        let strong_node_claims_engine = Arc::new(StrongNodeClaimsEngine::new(true, &config.network_name(), &app_data_dir));
        let unified_node_identity = match load_or_create_identity(&app_data_dir, &config.network_name()) {
            Ok(identity) => identity,
            Err(err) => {
                warn!("failed loading persistent unified node identity: {err}; falling back to ephemeral identity");
                create_ephemeral_identity(&config.network_name()).expect("failed creating ephemeral unified node identity")
            }
        };

        let orphan_resolution_range = BASELINE_ORPHAN_RESOLUTION_RANGE + (config.bps() as f64).log2().ceil() as u32;

        // The maximum amount of orphans allowed in the orphans pool. This number is an approximation
        // of how many orphans there can possibly be on average bounded by an upper bound.
        let max_orphans = (2u64.pow(orphan_resolution_range) as usize * config.ghostdag_k as usize).min(MAX_ORPHANS_UPPER_BOUND);
        Self {
            inner: Arc::new(FlowContextInner {
                node_id: Uuid::new_v4().into(),
                unified_node_identity: Arc::new(unified_node_identity),
                consensus_manager,
                orphans_pool: AsyncRwLock::new(OrphanBlocksPool::new(max_orphans)),
                shared_block_requests: Arc::new(Mutex::new(HashMap::new())),
                transactions_spread: AsyncRwLock::new(TransactionsSpread::new(
                    hub.clone(),
                    Duration::from_millis(config.tx_relay_broadcast_interval_ms),
                )),
                shared_transaction_requests: Arc::new(Mutex::new(HashMap::new())),
                is_ibd_running: Default::default(),
                ibd_metadata: Default::default(),
                hub,
                address_manager,
                connection_manager: Default::default(),
                autoban_enabled,
                misbehaving_peer_scores: Default::default(),
                inbound_connection_rate_limit: Default::default(),
                hfa_bridge: Default::default(),
                strong_node_claims_engine,
                mining_manager,
                tick_service,
                notification_root,
                quantum_handshake_mode_state: AtomicU8::new(QUANTUM_HANDSHAKE_STATE_UNKNOWN),
                quantum_handshake_start_logged: AtomicBool::new(false),
                quantum_handshake_key_sample_logged: AtomicBool::new(false),
                block_event_logger: if config.bps() > 1 { Some(BlockEventLogger::new(config.bps() as usize)) } else { None },
                orphan_resolution_range,
                max_orphans,
                config,
            }),
        }
    }

    pub fn block_invs_channel_size(&self) -> usize {
        self.config.bps() as usize * Router::incoming_flow_baseline_channel_size()
    }

    pub fn orphan_resolution_range(&self) -> u32 {
        self.orphan_resolution_range
    }

    pub fn max_orphans(&self) -> usize {
        self.max_orphans
    }

    pub fn start_async_services(&self) {
        info!("Quantum-safe ML-KEM-1024 handshake support enabled (ephemeral per-connection keys; no static startup key loaded)");
        if let Some(logger) = self.block_event_logger.as_ref() {
            logger.start();
        }
        let ctx = self.clone();
        tokio::spawn(async move {
            loop {
                match ctx.tick_service.tick(STRONG_NODES_TICK_INTERVAL).await {
                    cryptix_core::task::tick::TickReason::Wakeup => ctx.run_strong_node_claims_tick_once().await,
                    cryptix_core::task::tick::TickReason::Shutdown => break,
                }
            }
            ctx.strong_node_claims_engine.best_effort_flush();
        });
    }

    pub fn set_connection_manager(&self, connection_manager: Arc<ConnectionManager>) {
        self.connection_manager.write().replace(connection_manager);
    }

    pub fn drop_connection_manager(&self) {
        self.strong_node_claims_engine.best_effort_flush();
        self.connection_manager.write().take();
    }

    pub fn connection_manager(&self) -> Option<Arc<ConnectionManager>> {
        self.connection_manager.read().clone()
    }

    fn register_inbound_connection_attempt(&self, ip: IpAddr) -> InboundConnectionRateLimitVerdict {
        let now = Instant::now();
        let mut rate_limit = self.inbound_connection_rate_limit.lock();

        // Keep this table bounded over time and by size.
        rate_limit.retain(|_, record| now.saturating_duration_since(record.last_seen) <= MISBEHAVIOR_FORGET_AFTER);

        let record = rate_limit.entry(ip).or_insert_with(|| InboundConnectionRateLimitRecord {
            attempts: VecDeque::new(),
            last_penalty: None,
            last_seen: now,
        });

        while let Some(front) = record.attempts.front().copied() {
            if now.saturating_duration_since(front) > INBOUND_CONNECTION_RATE_LIMIT_WINDOW {
                record.attempts.pop_front();
            } else {
                break;
            }
        }
        record.attempts.push_back(now);
        record.last_seen = now;

        let attempts_in_window = record.attempts.len();
        let allowed = attempts_in_window <= INBOUND_CONNECTION_RATE_LIMIT_MAX_ATTEMPTS;
        let should_penalize = if allowed {
            false
        } else {
            let can_penalize = record
                .last_penalty
                .is_none_or(|last| now.saturating_duration_since(last) >= INBOUND_CONNECTION_RATE_LIMIT_STRIKE_COOLDOWN);
            if can_penalize {
                record.last_penalty = Some(now);
            }
            can_penalize
        };

        if rate_limit.len() > INBOUND_CONNECTION_RATE_LIMIT_MAX_TRACKED_IPS {
            let overflow = rate_limit.len() - INBOUND_CONNECTION_RATE_LIMIT_MAX_TRACKED_IPS;
            let mut by_age = rate_limit.iter().map(|(tracked_ip, rec)| (*tracked_ip, rec.last_seen)).collect::<Vec<_>>();
            by_age.sort_by_key(|(_, last_seen)| *last_seen);
            for (old_ip, _) in by_age.into_iter().take(overflow) {
                rate_limit.remove(&old_ip);
            }
        }

        InboundConnectionRateLimitVerdict { allowed, attempts_in_window, should_penalize }
    }

    async fn enforce_inbound_connection_rate_limit(&self, router: &Arc<Router>) -> Result<(), ProtocolError> {
        if !self.autoban_enabled || router.is_outbound() {
            return Ok(());
        }

        let ip = router.net_address().ip();
        let verdict = self.register_inbound_connection_attempt(ip);
        if verdict.allowed {
            return Ok(());
        }

        let reason = format!(
            "inbound connection rate limit exceeded for {} ({} attempts in {}s, max {})",
            ip,
            verdict.attempts_in_window,
            INBOUND_CONNECTION_RATE_LIMIT_WINDOW.as_secs(),
            INBOUND_CONNECTION_RATE_LIMIT_MAX_ATTEMPTS
        );
        if verdict.should_penalize {
            self.report_misbehaving_peer(router, &reason).await;
        }

        Err(ProtocolError::OtherOwned(reason))
    }

    pub async fn report_misbehaving_peer(&self, router: &Arc<Router>, reason: &str) {
        if !self.autoban_enabled {
            warn!("Auto-ban disabled: misbehaving peer {} ({})", router.net_address(), reason);
            return;
        }

        let ip = router.net_address().ip();
        let identity = self.misbehavior_identity_for_router(router);
        let now = Instant::now();

        let (score, should_ban) = {
            let mut scores = self.misbehaving_peer_scores.lock();
            scores.retain(|_, record| now.saturating_duration_since(record.last_seen) <= MISBEHAVIOR_FORGET_AFTER);

            let record = scores.entry(identity).or_insert(MisbehaviorRecord { score: 0, last_seen: now });
            let elapsed = now.saturating_duration_since(record.last_seen);
            let decay_steps = (elapsed.as_secs() / MISBEHAVIOR_DECAY_INTERVAL.as_secs()) as u32;
            record.score = record.score.saturating_sub(decay_steps).saturating_add(1);
            record.last_seen = now;

            let score = record.score;
            let should_ban = score >= MISBEHAVIOR_BAN_SCORE;

            if should_ban {
                scores.remove(&identity);
            } else if scores.len() > MISBEHAVIOR_MAX_TRACKED_PEERS {
                let overflow = scores.len() - MISBEHAVIOR_MAX_TRACKED_PEERS;
                let mut by_age = scores.iter().map(|(identity, record)| (*identity, record.last_seen)).collect::<Vec<_>>();
                by_age.sort_by_key(|(_, last_seen)| *last_seen);
                for (old_identity, _) in by_age.into_iter().take(overflow) {
                    scores.remove(&old_identity);
                }
            }

            (score, should_ban)
        };

        if should_ban {
            if let Some(connection_manager) = self.connection_manager() {
                match identity {
                    MisbehaviorIdentity::UnifiedNodeId(node_id) => {
                        warn!(
                            "Auto-ban: banning unified node ID {} after {}/{} strikes ({})",
                            ConnectionManager::encode_node_id_hex(&node_id),
                            score,
                            MISBEHAVIOR_BAN_SCORE,
                            reason
                        );
                        connection_manager.ban_unified_node_id(node_id).await;
                    }
                    MisbehaviorIdentity::Ip(_) => {
                        warn!(
                            "Auto-ban: banning peer {} after {}/{} strikes ({})",
                            router.net_address(),
                            score,
                            MISBEHAVIOR_BAN_SCORE,
                            reason
                        );
                        connection_manager.ban(ip).await;
                    }
                }
            } else {
                warn!(
                    "Auto-ban: peer {} reached {}/{} strikes ({}), but no connection manager is available",
                    router.net_address(),
                    score,
                    MISBEHAVIOR_BAN_SCORE,
                    reason
                );
            }
        } else {
            warn!("Auto-ban: peer {} strike {}/{} ({})", router.net_address(), score, MISBEHAVIOR_BAN_SCORE, reason);
        }
    }

    fn misbehavior_identity_for_router(&self, router: &Router) -> MisbehaviorIdentity {
        if let Some(node_id) = router.properties().unified_node_id {
            return MisbehaviorIdentity::UnifiedNodeId(node_id);
        }
        MisbehaviorIdentity::Ip(router.net_address().ip())
    }

    pub fn set_hfa_bridge(&self, bridge: Arc<dyn HfaP2pBridge>) {
        self.hfa_bridge.write().replace(bridge);
    }

    pub fn hfa_bridge(&self) -> Option<Arc<dyn HfaP2pBridge>> {
        self.hfa_bridge.read().clone()
    }

    pub fn is_hfa_p2p_enabled(&self) -> bool {
        self.hfa_bridge().map(|bridge| bridge.hfa_enabled()).unwrap_or(false)
    }

    pub fn strong_node_claims_snapshot(&self) -> StrongNodeClaimsRuntimeSnapshot {
        self.strong_node_claims_engine.snapshot(self.is_payload_hf_active())
    }

    pub fn is_payload_hf_active(&self) -> bool {
        let virtual_daa_score = self.consensus().unguarded_session().get_virtual_daa_score();
        virtual_daa_score >= self.config.params.payload_hf_activation_daa_score
    }

    fn log_quantum_handshake_mode_transition(&self, enforce_quantum_handshake: bool) {
        let next_state = if enforce_quantum_handshake { QUANTUM_HANDSHAKE_STATE_ENFORCED } else { QUANTUM_HANDSHAKE_STATE_LEGACY };
        let previous_state = self.quantum_handshake_mode_state.swap(next_state, Ordering::SeqCst);
        if previous_state == next_state {
            return;
        }

        if next_state == QUANTUM_HANDSHAKE_STATE_ENFORCED {
            info!("Hardfork reached: switching to quantum-safe handshake (ML-KEM-1024 enforced)");
            return;
        }

        if previous_state == QUANTUM_HANDSHAKE_STATE_ENFORCED {
            warn!("Quantum-safe handshake enforcement disabled; returning to legacy-compatible handshake mode");
        } else {
            info!("Handshake mode initialized: legacy-compatible (quantum-safe ML-KEM-1024 is not enforced)");
        }
    }

    fn log_quantum_handshake_startup_once(&self, enforce_quantum_handshake: bool) {
        if self.quantum_handshake_start_logged.swap(true, Ordering::SeqCst) {
            return;
        }
        if enforce_quantum_handshake {
            info!("Peer handshake started: running in quantum-safe mode (ML-KEM-1024 enforced)");
        } else {
            info!("Peer handshake started: running in legacy-compatible mode");
        }
    }

    fn log_quantum_handshake_key_sample_once(&self, public_key: &[u8]) {
        if self.quantum_handshake_key_sample_logged.swap(true, Ordering::SeqCst) {
            return;
        }
        let sample = short_hex_for_log(public_key);
        info!("Quantum-safe ML-KEM-1024 handshake key policy: using ephemeral per-connection keys ({})", sample);
    }

    pub fn is_strong_node_claims_p2p_enabled(&self) -> bool {
        self.strong_node_claims_engine.should_advertise_service_bit(self.is_payload_hf_active())
    }

    pub fn consensus(&self) -> ConsensusInstance {
        self.consensus_manager.consensus()
    }

    pub fn hub(&self) -> &Hub {
        &self.hub
    }

    fn unrestricted_peer_keys(&self) -> Vec<PeerKey> {
        self.hub.active_peers().into_iter().filter(|peer| !peer.properties().anti_fraud_restricted).map(|peer| peer.key()).collect()
    }

    pub async fn broadcast_to_unrestricted_peers(&self, msg: CryptixdMessage) {
        for target in self.unrestricted_peer_keys() {
            let _ = self.hub.send(target, msg.clone()).await;
        }
    }

    pub async fn broadcast_many_to_unrestricted_peers(&self, msgs: Vec<CryptixdMessage>) {
        if msgs.is_empty() {
            return;
        }
        let targets = self.unrestricted_peer_keys();
        for target in targets {
            for msg in msgs.iter().cloned() {
                let _ = self.hub.send(target, msg).await;
            }
        }
    }

    pub fn mining_manager(&self) -> &MiningManagerProxy {
        &self.mining_manager
    }

    pub fn try_set_ibd_running(&self, peer: PeerKey, relay_daa_score: u64) -> Option<IbdRunningGuard> {
        if self.is_ibd_running.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
            self.ibd_metadata.write().replace(IbdMetadata { peer, daa_score: relay_daa_score });
            Some(IbdRunningGuard { indicator: self.is_ibd_running.clone() })
        } else {
            None
        }
    }

    pub fn is_ibd_running(&self) -> bool {
        self.is_ibd_running.load(Ordering::SeqCst)
    }

    /// If IBD is running, returns the IBD peer we are syncing from
    pub fn ibd_peer_key(&self) -> Option<PeerKey> {
        if self.is_ibd_running() {
            self.ibd_metadata.read().map(|md| md.peer)
        } else {
            None
        }
    }

    /// If IBD is running, returns the DAA score of the relay block which triggered it
    pub fn ibd_relay_daa_score(&self) -> Option<u64> {
        if self.is_ibd_running() {
            self.ibd_metadata.read().map(|md| md.daa_score)
        } else {
            None
        }
    }

    fn try_adding_request_impl(req: Hash, map: &Arc<Mutex<HashMap<Hash, RequestScopeMetadata>>>) -> Option<RequestScope<Hash>> {
        match map.lock().entry(req) {
            Entry::Occupied(mut e) => {
                if e.get().obtained {
                    None
                } else {
                    let now = Instant::now();
                    if now > e.get().timestamp + REQUEST_SCOPE_WAIT_TIME {
                        e.get_mut().timestamp = now;
                        Some(RequestScope::new(map.clone(), req))
                    } else {
                        None
                    }
                }
            }
            Entry::Vacant(e) => {
                e.insert(RequestScopeMetadata { timestamp: Instant::now(), obtained: false });
                Some(RequestScope::new(map.clone(), req))
            }
        }
    }

    pub fn try_adding_block_request(&self, req: Hash) -> Option<RequestScope<Hash>> {
        Self::try_adding_request_impl(req, &self.shared_block_requests)
    }

    pub fn try_adding_transaction_request(&self, req: TransactionId) -> Option<RequestScope<TransactionId>> {
        Self::try_adding_request_impl(req, &self.shared_transaction_requests)
    }

    pub async fn add_orphan(&self, consensus: &ConsensusProxy, orphan_block: Block) -> Option<OrphanOutput> {
        self.orphans_pool.write().await.add_orphan(consensus, orphan_block).await
    }

    pub async fn is_known_orphan(&self, hash: Hash) -> bool {
        self.orphans_pool.read().await.is_known_orphan(hash)
    }

    pub async fn get_orphan_roots_if_known(&self, consensus: &ConsensusProxy, orphan: Hash) -> OrphanOutput {
        self.orphans_pool.read().await.get_orphan_roots_if_known(consensus, orphan).await
    }

    pub async fn unorphan_blocks(&self, consensus: &ConsensusProxy, root: Hash) -> Vec<(Block, BlockValidationFuture)> {
        let (blocks, block_tasks, virtual_state_tasks) = self.orphans_pool.write().await.unorphan_blocks(consensus, root).await;
        let mut unorphaned_blocks = Vec::with_capacity(blocks.len());
        let results = join_all(block_tasks).await;
        for ((block, result), virtual_state_task) in blocks.into_iter().zip(results).zip(virtual_state_tasks) {
            match result {
                Ok(_) => {
                    unorphaned_blocks.push((block, virtual_state_task));
                }
                Err(e) => warn!("Validation failed for orphan block {}: {}", block.hash(), e),
            }
        }

        // Log or send to event logger
        if !unorphaned_blocks.is_empty() {
            if let Some(logger) = self.block_event_logger.as_ref() {
                logger.log(BlockLogEvent::Unorphaned(unorphaned_blocks[0].0.hash(), unorphaned_blocks.len()));
            } else {
                match unorphaned_blocks.len() {
                    1 => info!("Unorphaned block {}", unorphaned_blocks[0].0.hash()),
                    n => info!("Unorphaned {} blocks: {}", n, unorphaned_blocks.iter().map(|b| b.0.hash()).reusable_format(", ")),
                }
            }
        }
        unorphaned_blocks
    }

    pub async fn revalidate_orphans(&self, consensus: &ConsensusProxy) -> (Vec<Hash>, Vec<BlockValidationFuture>) {
        self.orphans_pool.write().await.revalidate_orphans(consensus).await
    }

    /// Adds the rpc-submitted block to the DAG and propagates it to peers.
    pub async fn submit_rpc_block(&self, consensus: &ConsensusProxy, block: Block) -> Result<(), ProtocolError> {
        if block.transactions.is_empty() {
            return Err(RuleError::NoTransactions)?;
        }
        let hash = block.hash();
        let BlockValidationFutures { block_task, virtual_state_task } = consensus.validate_and_insert_block(block.clone());
        if let Err(err) = block_task.await {
            warn!("Validation failed for block {}: {}", hash, err);
            return Err(err)?;
        }
        // Broadcast as soon as the block has been validated and inserted into the DAG
        self.broadcast_to_unrestricted_peers(make_message!(Payload::InvRelayBlock, InvRelayBlockMessage { hash: Some(hash.into()) }))
            .await;

        self.on_new_block(consensus, Default::default(), block, virtual_state_task).await;
        self.log_block_event(BlockLogEvent::Submit(hash));
        self.broadcast_local_block_producer_claim(hash).await;

        Ok(())
    }

    pub fn log_block_event(&self, event: BlockLogEvent) {
        if let Some(logger) = self.block_event_logger.as_ref() {
            logger.log(event)
        } else {
            match event {
                BlockLogEvent::Relay(hash) => info!("Accepted block {} via relay", hash),
                BlockLogEvent::Submit(hash) => info!("Accepted block {} via submit block", hash),
                BlockLogEvent::Orphaned(orphan, roots_count) => {
                    info!("Received a block with {} missing ancestors, adding to orphan pool: {}", roots_count, orphan)
                }
                _ => {}
            }
        }
    }

    /// Updates the mempool after a new block arrival, relays newly unorphaned transactions
    /// and possibly rebroadcast manually added transactions when not in IBD.
    ///
    /// _GO-CRYPTIXD: OnNewBlock + broadcastTransactionsAfterBlockAdded_
    pub async fn on_new_block(
        &self,
        consensus: &ConsensusProxy,
        ancestor_batch: BlockProcessingBatch,
        block: Block,
        virtual_state_task: BlockValidationFuture,
    ) {
        let hash = block.hash();
        let mut blocks = self.unorphan_blocks(consensus, hash).await;

        // Broadcast unorphaned blocks
        let msgs = blocks
            .iter()
            .map(|(b, _)| make_message!(Payload::InvRelayBlock, InvRelayBlockMessage { hash: Some(b.hash().into()) }))
            .collect();
        self.broadcast_many_to_unrestricted_peers(msgs).await;

        // Process blocks in topological order
        blocks.sort_by(|a, b| a.0.header.blue_work.partial_cmp(&b.0.header.blue_work).unwrap());
        // Use a ProcessQueue so we get rid of duplicates
        let mut transactions_to_broadcast = ProcessQueue::new();
        for (block, virtual_state_task) in ancestor_batch.zip().chain(once((block, virtual_state_task))).chain(blocks.into_iter()) {
            // We only care about waiting for virtual to process the block at this point, before proceeding with post-processing
            // actions such as updating the mempool. We know this will not err since `block_task` already completed w/o error
            let _ = virtual_state_task.await;
            if let Ok(txs) = self
                .mining_manager()
                .clone()
                .handle_new_block_transactions(consensus, block.header.daa_score, block.transactions.clone())
                .await
            {
                transactions_to_broadcast.enqueue_chunk(txs.into_iter().map(|x| x.id()));
            }
        }

        // Transaction relay is disabled if the node is out of sync and thus not mining
        if !consensus.async_is_nearly_synced().await {
            self.refresh_strong_node_claims_window(consensus).await;
            return;
        }

        // TODO: Throttle these transactions as well if needed
        self.broadcast_transactions(transactions_to_broadcast, false).await;

        if self.should_run_mempool_scanning_task().await {
            // Spawn a task executing the removal of expired low priority transactions and, if time has come too,
            // the revalidation of high priority transactions.
            //
            // The TransactionSpread member ensures at most one instance of this task is running at any
            // given time.
            let mining_manager = self.mining_manager().clone();
            let consensus_clone = consensus.clone();
            let context = self.clone();
            debug!("<> Starting mempool scanning task #{}...", self.mempool_scanning_job_count().await);
            tokio::spawn(async move {
                mining_manager.clone().expire_low_priority_transactions(&consensus_clone).await;
                if context.should_rebroadcast().await {
                    let (tx, mut rx) = unbounded_channel();
                    tokio::spawn(async move {
                        mining_manager.revalidate_high_priority_transactions(&consensus_clone, tx).await;
                    });
                    while let Some(transactions) = rx.recv().await {
                        let _ = context
                            .broadcast_transactions(
                                transactions,
                                true, // We throttle high priority even when the network is not flooded since they will be rebroadcast if not accepted within reasonable time.
                            )
                            .await;
                    }
                }
                context.mempool_scanning_is_done().await;
                debug!("<> Mempool scanning task is done");
            });
        }
        self.refresh_strong_node_claims_window(consensus).await;
    }

    /// Notifies that the UTXO set was reset due to pruning point change via IBD.
    pub fn on_pruning_point_utxoset_override(&self) {
        // Notifications from the flow context might be ignored if the inner channel is already closing
        // due to global shutdown, hence we ignore the possible error
        let _ = self.notification_root.notify(Notification::PruningPointUtxoSetOverride(PruningPointUtxoSetOverrideNotification {}));
    }

    /// Notifies that a transaction has been added to the mempool.
    pub async fn on_transaction_added_to_mempool(&self) {
        // TODO: call a handler function or a predefined registered service
    }

    /// Adds the rpc-submitted transaction to the mempool and propagates it to peers.
    ///
    /// Transactions submitted through rpc are considered high priority. This definition does not affect the tx selection algorithm
    /// but only changes how we manage the lifetime of the tx. A high-priority tx does not expire and is repeatedly rebroadcasted to
    /// peers
    pub async fn submit_rpc_transaction(
        &self,
        consensus: &ConsensusProxy,
        transaction: Transaction,
        orphan: Orphan,
    ) -> Result<(), ProtocolError> {
        let transaction_insertion = self
            .mining_manager()
            .clone()
            .validate_and_insert_transaction(consensus, transaction, Priority::High, orphan, RbfPolicy::Forbidden)
            .await?;
        self.broadcast_transactions(
            transaction_insertion.accepted.iter().map(|x| x.id()),
            false, // RPC transactions are considered high priority, so we don't want to throttle them
        )
        .await;
        Ok(())
    }

    /// Replaces the rpc-submitted transaction into the mempool and propagates it to peers.
    ///
    /// Returns the removed mempool transaction on successful replace by fee.
    ///
    /// Transactions submitted through rpc are considered high priority. This definition does not affect the tx selection algorithm
    /// but only changes how we manage the lifetime of the tx. A high-priority tx does not expire and is repeatedly rebroadcasted to
    /// peers
    pub async fn submit_rpc_transaction_replacement(
        &self,
        consensus: &ConsensusProxy,
        transaction: Transaction,
    ) -> Result<Arc<Transaction>, ProtocolError> {
        let transaction_insertion = self
            .mining_manager()
            .clone()
            .validate_and_insert_transaction(consensus, transaction, Priority::High, Orphan::Forbidden, RbfPolicy::Mandatory)
            .await?;
        self.broadcast_transactions(
            transaction_insertion.accepted.iter().map(|x| x.id()),
            false, // RPC transactions are considered high priority, so we don't want to throttle them
        )
        .await;
        // The combination of args above of Orphan::Forbidden and RbfPolicy::Mandatory should always result
        // in a removed transaction returned, however we prefer failing gracefully in case of future internal mempool changes
        transaction_insertion.removed.ok_or(ProtocolError::Other(
            "Replacement transaction was actually accepted but the *replaced* transaction was not returned from the mempool",
        ))
    }

    /// Returns true if the time has come for running the task cleaning mempool transactions.
    async fn should_run_mempool_scanning_task(&self) -> bool {
        self.transactions_spread.write().await.should_run_mempool_scanning_task()
    }

    /// Returns true if the time has come for a rebroadcast of the mempool high priority transactions.
    async fn should_rebroadcast(&self) -> bool {
        self.transactions_spread.read().await.should_rebroadcast()
    }

    async fn mempool_scanning_job_count(&self) -> u64 {
        self.transactions_spread.read().await.mempool_scanning_job_count()
    }

    async fn mempool_scanning_is_done(&self) {
        self.transactions_spread.write().await.mempool_scanning_is_done()
    }

    /// Add the given transactions IDs to a set of IDs to broadcast. The IDs will be broadcasted to all
    /// non-restricted peers within transaction Inv messages.
    ///
    /// The broadcast itself may happen only during a subsequent call to this function since it is done at most
    /// after a predefined interval or when the queue length is larger than the Inv message capacity.
    pub async fn broadcast_transactions<I: IntoIterator<Item = TransactionId>>(&self, transaction_ids: I, should_throttle: bool) {
        self.transactions_spread.write().await.broadcast_transactions(transaction_ids, should_throttle).await
    }

    pub async fn broadcast_fast_intent(&self, intent: &FastIntentP2pData) {
        if !self.is_hfa_p2p_enabled() {
            return;
        }

        let msg = make_message!(
            Payload::FastIntent,
            FastIntentMessage {
                intent_id: Some(intent.intent_id.into()),
                base_transaction: Some((&intent.base_tx).into()),
                intent_nonce: intent.intent_nonce,
                client_created_at_ms: intent.client_created_at_ms,
                max_fee: intent.max_fee,
            }
        );
        for peer in self.hub.active_peers() {
            if (peer.properties().services & HFA_P2P_SERVICE_BIT) == 0 {
                continue;
            }
            if peer.properties().anti_fraud_restricted {
                continue;
            }
            let _ = self.hub.send(peer.key(), msg.clone()).await;
        }
    }

    pub async fn broadcast_fast_microblock(&self, microblock: FastMicroblockP2pData) {
        if !self.is_hfa_p2p_enabled() {
            return;
        }

        let msg = make_message!(
            Payload::FastMicroblock,
            FastMicroblockMessage {
                microblock_time_ms: microblock.microblock_time_ms,
                intent_ids: microblock.intent_ids.iter().map(Into::into).collect(),
            }
        );
        for peer in self.hub.active_peers() {
            if (peer.properties().services & HFA_P2P_SERVICE_BIT) == 0 {
                continue;
            }
            if peer.properties().anti_fraud_restricted {
                continue;
            }
            let _ = self.hub.send(peer.key(), msg.clone()).await;
        }
    }

    pub async fn broadcast_outbound_fast_microblocks(&self) {
        let Some(bridge) = self.hfa_bridge() else {
            return;
        };
        if !bridge.hfa_enabled() {
            return;
        }
        for microblock in bridge.take_outbound_fast_microblocks() {
            self.broadcast_fast_microblock(microblock).await;
        }
    }

    async fn run_strong_node_claims_tick_once(&self) {
        self.strong_node_claims_engine.maybe_flush();
    }

    pub async fn handle_block_producer_claim(&self, router: &Arc<Router>, message: BlockProducerClaimV1Message) {
        let outcome = self.strong_node_claims_engine.ingest_claim(&message, self.is_payload_hf_active());
        match outcome {
            ClaimIngestOutcome::Accepted { pending: _ } => {
                self.broadcast_block_producer_claim(message, Some(router.key())).await;
            }
            ClaimIngestOutcome::Strike { reason, node_id } => {
                if let Some(node_id) = node_id {
                    if let Some(connection_manager) = self.connection_manager() {
                        if connection_manager.is_unified_node_id_banned(&node_id) {
                            connection_manager.ban(router.net_address().ip()).await;
                            return;
                        }
                    }
                }
                self.report_misbehaving_peer(router, &reason).await;
            }
            ClaimIngestOutcome::Ignored | ClaimIngestOutcome::Dropped => {}
        }
    }

    pub async fn broadcast_block_producer_claim(&self, message: BlockProducerClaimV1Message, exclude_peer: Option<PeerKey>) {
        if !self.is_strong_node_claims_p2p_enabled() {
            return;
        }

        let mut targets = self
            .hub
            .active_peers()
            .into_iter()
            .filter_map(|peer| {
                if (peer.properties().services & STRONG_NODE_CLAIMS_P2P_SERVICE_BIT) == 0 {
                    return None;
                }
                if peer.properties().anti_fraud_restricted {
                    return None;
                }
                if exclude_peer.is_some_and(|excluded| excluded == peer.key()) {
                    return None;
                }
                Some(peer.key())
            })
            .collect::<Vec<_>>();
        if targets.is_empty() {
            return;
        }
        let target_len = targets.len();
        if target_len > STRONG_NODE_CLAIMS_GOSSIP_FANOUT {
            let base = (unix_now() as usize) % target_len;
            targets = (0..STRONG_NODE_CLAIMS_GOSSIP_FANOUT).map(|offset| targets[(base + offset) % target_len]).collect();
        }
        let msg = make_message!(Payload::BlockProducerClaimV1, message);
        for target in targets {
            let _ = self.hub.send(target, msg.clone()).await;
        }
    }

    async fn broadcast_local_block_producer_claim(&self, block_hash: Hash) {
        if !self.is_strong_node_claims_p2p_enabled() {
            return;
        }
        match self.strong_node_claims_engine.build_local_claim(block_hash, self.unified_node_identity.as_ref()) {
            Ok(message) => {
                let _ = self.strong_node_claims_engine.ingest_claim(&message, self.is_payload_hf_active());
                self.broadcast_block_producer_claim(message, None).await;
            }
            Err(err) => warn!("failed building local block producer claim for {}: {}", block_hash, err),
        }
    }

    async fn refresh_strong_node_claims_window(&self, consensus: &ConsensusProxy) {
        if !self.is_strong_node_claims_p2p_enabled() {
            return;
        }
        let session = consensus.clone();
        let sink = session.async_get_sink().await;
        let previous = self.strong_node_claims_engine.last_sink();
        match previous {
            Some(prev) if prev != sink => {
                if let Ok(chain_path) = session.async_get_virtual_chain_from_block(prev, None).await {
                    self.strong_node_claims_engine.apply_chain_path_update(chain_path, sink, self.is_payload_hf_active());
                    self.strong_node_claims_engine.maybe_flush();
                }
            }
            None => {
                let mut path = ChainPath::default();
                path.added.push(sink);
                self.strong_node_claims_engine.apply_chain_path_update(path, sink, self.is_payload_hf_active());
                self.strong_node_claims_engine.maybe_flush();
            }
            _ => {}
        }
    }
}

#[async_trait]
impl ConnectionInitializer for FlowContext {
    async fn initialize_connection(&self, router: Arc<Router>) -> Result<(), ProtocolError> {
        if let Some(connection_manager) = self.connection_manager() {
            if connection_manager.is_banned(&router.net_address()).await {
                return Err(ProtocolError::OtherOwned(format!("peer {} is banned", router.net_address().ip())));
            }
        }
        self.enforce_inbound_connection_rate_limit(&router).await?;

        // Build the handshake object and subscribe to handshake messages
        let mut handshake = CryptixdHandshake::new(&router);

        // We start the router receive loop only after we registered to handshake routes
        router.start();

        let network_name = self.config.network_name();

        let local_address = self.address_manager.lock().best_local_address();

        // Build the local version message
        // Subnets are not currently supported
        let mut self_version_message = Version::new(local_address, self.node_id, network_name.clone(), None, PROTOCOL_VERSION);
        self_version_message.add_user_agent(name(), version(), &self.config.user_agent_comments);
        let local_anti_fraud_hash_window = self.connection_manager().map(|cm| cm.anti_fraud_hash_window()).unwrap_or([[0u8; 32]; 3]);
        self_version_message.anti_fraud_hashes = local_anti_fraud_hash_window.to_vec();
        self_version_message.node_pubkey_xonly = Some(self.unified_node_identity.pubkey_xonly);
        self_version_message.node_pow_nonce = Some(self.unified_node_identity.pow_nonce);
        let local_node_challenge_nonce = rand::random::<u64>();
        self_version_message.node_challenge_nonce = Some(local_node_challenge_nonce);
        let (local_pq_ml_kem1024_public_key, local_pq_ml_kem1024_private_key) = generate_mlkem1024_keypair();
        if local_pq_ml_kem1024_public_key.len() != PQ_MLKEM1024_PUBLIC_KEY_SIZE {
            return Err(ProtocolError::OtherOwned(format!(
                "local ML-KEM-1024 public key must be exactly {PQ_MLKEM1024_PUBLIC_KEY_SIZE} bytes"
            )));
        }
        self.log_quantum_handshake_key_sample_once(local_pq_ml_kem1024_public_key.as_slice());
        self_version_message.pq_ml_kem1024_pubkey = Some(local_pq_ml_kem1024_public_key);
        if self.is_hfa_p2p_enabled() {
            self_version_message.services |= HFA_P2P_SERVICE_BIT;
        }
        if self.is_strong_node_claims_p2p_enabled() {
            self_version_message.services |= STRONG_NODE_CLAIMS_P2P_SERVICE_BIT;
        }
        // TODO: get number of live services
        // TODO: disable_relay_tx from config/cmd

        // Perform the handshake
        let peer_version_message = handshake.handshake(self_version_message.into()).await?;
        // Get time_offset as accurate as possible by computing right after the handshake
        let time_offset = unix_now() as i64 - peer_version_message.timestamp;

        let peer_version: Version = peer_version_message.try_into()?;
        let network_code = network_code_from_name(&network_name)
            .ok_or_else(|| ProtocolError::OtherOwned(format!("unsupported network for node identity `{network_name}`")))?;
        let (peer_unified_node_id, peer_pubkey_xonly) = match (peer_version.node_pubkey_xonly, peer_version.node_pow_nonce) {
            (Some(pubkey), Some(pow_nonce)) => {
                if !is_valid_pow_nonce(network_code, &pubkey, pow_nonce) {
                    return Err(ProtocolError::OtherOwned("peer sent invalid node identity proof-of-work".to_string()));
                }
                (Some(compute_node_id(&pubkey)), Some(pubkey))
            }
            (None, None) => (None, None),
            _ => return Err(ProtocolError::OtherOwned("peer sent incomplete node identity handshake fields".to_string())),
        };
        let peer_node_challenge_nonce = peer_version.node_challenge_nonce;
        let peer_pq_ml_kem1024_public_key = peer_version.pq_ml_kem1024_pubkey.clone();
        if peer_unified_node_id.is_none() && peer_node_challenge_nonce.is_some() {
            return Err(ProtocolError::OtherOwned("peer sent node challenge nonce without node identity fields".to_string()));
        }
        router.set_identity(peer_version.id);
        // Avoid duplicate connections
        if self.hub.has_peer(router.key()) {
            return Err(ProtocolError::PeerAlreadyExists(router.key()));
        }
        if !is_compatible_peer_network(&network_name, &peer_version.network) {
            return Err(ProtocolError::WrongNetwork(network_name, peer_version.network));
        }

        let payload_hf_active = self.is_payload_hf_active();
        let anti_fraud_runtime_enabled = self.connection_manager().map(|cm| cm.is_antifraud_runtime_enabled()).unwrap_or(false);
        let enforce_hardfork_core = payload_hf_active;
        let enforce_anti_fraud = enforce_hardfork_core && anti_fraud_runtime_enabled;
        self.log_quantum_handshake_mode_transition(enforce_hardfork_core);
        self.log_quantum_handshake_startup_once(enforce_hardfork_core);
        debug!(
            "Starting handshake with peer {} in {} mode",
            router,
            if enforce_hardfork_core { "quantum-safe (ML-KEM-1024 enforced)" } else { "legacy-compatible" }
        );

        if enforce_hardfork_core && peer_unified_node_id.is_none() {
            return Err(ProtocolError::OtherOwned("peer missing mandatory unified node identity after hardfork".to_string()));
        }
        if enforce_hardfork_core && peer_node_challenge_nonce.is_none() {
            return Err(ProtocolError::OtherOwned("peer missing mandatory node challenge nonce after hardfork".to_string()));
        }
        if enforce_hardfork_core && peer_pq_ml_kem1024_public_key.is_none() {
            return Err(ProtocolError::OtherOwned("peer missing mandatory ML-KEM-1024 public key after hardfork".to_string()));
        }
        if let Some(peer_node_id) = peer_unified_node_id {
            if peer_node_id == self.unified_node_identity.node_id {
                return Err(ProtocolError::LoopbackConnection(router.key()));
            }
            if let Some(connection_manager) = self.connection_manager() {
                if connection_manager.is_unified_node_id_banned(&peer_node_id) {
                    return Err(ProtocolError::OtherOwned("peer unified node identity is banned".to_string()));
                }
            }
        } else if self.node_id == router.identity() {
            // Legacy pre-HF fallback.
            return Err(ProtocolError::LoopbackConnection(router.key()));
        }

        debug!("protocol versions - self: {}, peer: {}", PROTOCOL_VERSION, peer_version.protocol_version);

        // Register all flows according to version
        let local_hfa_enabled = self.is_hfa_p2p_enabled();
        let peer_hfa_enabled = (peer_version.services & HFA_P2P_SERVICE_BIT) != 0;
        let hfa_capable = local_hfa_enabled && peer_hfa_enabled;
        let local_strong_node_claims_enabled = self.is_strong_node_claims_p2p_enabled();
        let peer_strong_node_claims_enabled = (peer_version.services & STRONG_NODE_CLAIMS_P2P_SERVICE_BIT) != 0;
        if enforce_hardfork_core && !peer_strong_node_claims_enabled {
            return Err(ProtocolError::OtherOwned("peer missing mandatory strong-node-claims service bit after hardfork".to_string()));
        }
        let strong_node_claims_capable = local_strong_node_claims_enabled && peer_strong_node_claims_enabled;
        debug!(
            "HFA P2P capability for peer {}: local_enabled={} peer_enabled={} peer_services=0x{:x} capable={}",
            router, local_hfa_enabled, peer_hfa_enabled, peer_version.services, hfa_capable
        );
        debug!(
            "Strong-Node-Claims P2P capability for peer {}: local_enabled={} peer_enabled={} peer_services=0x{:x} capable={}",
            router,
            local_strong_node_claims_enabled,
            peer_strong_node_claims_enabled,
            peer_version.services,
            strong_node_claims_capable
        );

        let anti_fraud_mode = if enforce_anti_fraud {
            self.connection_manager()
                .map(|cm| match anti_fraud_hash_window_from_vec(&peer_version.anti_fraud_hashes) {
                    Some(peer_hash_window) => cm.anti_fraud_mode_for_peer_hashes(&peer_hash_window),
                    None => AntiFraudMode::Restricted,
                })
                .unwrap_or(AntiFraudMode::Restricted)
        } else {
            AntiFraudMode::Full
        };

        let minimum_protocol_version = if enforce_hardfork_core { PROTOCOL_VERSION } else { MIN_PRE_HARD_FORK_PROTOCOL_VERSION };
        let (flows, applied_protocol_version) = match peer_version.protocol_version {
            // New protocol line.
            v if v >= PROTOCOL_VERSION => {
                if enforce_anti_fraud && anti_fraud_mode == AntiFraudMode::Restricted {
                    (v6::register_restricted(self.clone(), router.clone()), PROTOCOL_VERSION)
                } else {
                    (v6::register(self.clone(), router.clone(), hfa_capable, strong_node_claims_capable), PROTOCOL_VERSION)
                }
            }
            // Pre-HF compatibility lines.
            PRE_HARD_FORK_PROTOCOL_VERSION if !enforce_hardfork_core => {
                (v6::register(self.clone(), router.clone(), hfa_capable, strong_node_claims_capable), PRE_HARD_FORK_PROTOCOL_VERSION)
            }
            LEGACY_PROTOCOL_VERSION if !enforce_hardfork_core => {
                (v6::register(self.clone(), router.clone(), hfa_capable, strong_node_claims_capable), LEGACY_PROTOCOL_VERSION)
            }
            MIN_PRE_HARD_FORK_PROTOCOL_VERSION if !enforce_hardfork_core => (
                v5::register(self.clone(), router.clone(), hfa_capable, strong_node_claims_capable),
                MIN_PRE_HARD_FORK_PROTOCOL_VERSION,
            ),
            v => return Err(ProtocolError::VersionMismatch(minimum_protocol_version, v)),
        };

        // Build and register the peer properties
        let peer_properties = Arc::new(PeerProperties {
            user_agent: peer_version.user_agent.to_owned(),
            services: peer_version.services,
            advertised_protocol_version: peer_version.protocol_version,
            protocol_version: applied_protocol_version,
            disable_relay_tx: peer_version.disable_relay_tx,
            subnetwork_id: peer_version.subnetwork_id.to_owned(),
            time_offset,
            anti_fraud_hashes: peer_version.anti_fraud_hashes.clone(),
            anti_fraud_restricted: enforce_anti_fraud && anti_fraud_mode == AntiFraudMode::Restricted,
            unified_node_id: peer_unified_node_id,
        });
        router.set_properties(peer_properties);

        let local_ready_signature = match (peer_unified_node_id, peer_node_challenge_nonce) {
            (Some(peer_node_id), Some(peer_nonce)) => Some(
                sign_node_auth_proof(
                    self.unified_node_identity.as_ref(),
                    network_code,
                    &peer_node_id,
                    local_node_challenge_nonce,
                    peer_nonce,
                )
                .map_err(|err| ProtocolError::OtherOwned(format!("failed creating ready auth signature: {err}")))?,
            ),
            _ => None,
        };
        let local_ready_pq_payload = match (peer_unified_node_id, peer_node_challenge_nonce, peer_pq_ml_kem1024_public_key.as_deref())
        {
            (Some(peer_node_id), Some(peer_nonce), Some(peer_public_key)) => {
                let (ciphertext, shared_secret) = encapsulate_mlkem1024(peer_public_key)
                    .map_err(|err| ProtocolError::OtherOwned(format!("failed encapsulating ML-KEM-1024 payload: {err}")))?;
                let proof = compute_pq_handshake_proof(
                    network_code,
                    &self.unified_node_identity.node_id,
                    &peer_node_id,
                    local_node_challenge_nonce,
                    peer_nonce,
                    &shared_secret,
                );
                Some((ciphertext, proof.to_vec()))
            }
            (Some(_), Some(_), None) if enforce_hardfork_core => {
                return Err(ProtocolError::OtherOwned("peer missing mandatory ML-KEM-1024 public key after hardfork".to_string()))
            }
            _ => None,
        };
        let (local_ready_pq_ciphertext, local_ready_pq_proof) = local_ready_pq_payload.unwrap_or_else(|| (Vec::new(), Vec::new()));

        // Send and receive the ready signal
        let received_ready_message = handshake
            .exchange_ready_messages(cryptix_p2p_lib::pb::ReadyMessage {
                node_auth_signature: local_ready_signature.map(|value| value.to_vec()).unwrap_or_default(),
                pq_ml_kem1024_ciphertext: local_ready_pq_ciphertext,
                pq_handshake_proof: local_ready_pq_proof,
            })
            .await?;

        if let (Some(peer_node_id), Some(peer_pubkey), Some(peer_nonce)) =
            (peer_unified_node_id, peer_pubkey_xonly, peer_node_challenge_nonce)
        {
            if received_ready_message.node_auth_signature.is_empty() {
                if enforce_hardfork_core {
                    return Err(ProtocolError::OtherOwned("peer missing mandatory ready auth signature after hardfork".to_string()));
                }
            } else {
                let peer_signature: [u8; 64] = received_ready_message
                    .node_auth_signature
                    .as_slice()
                    .try_into()
                    .map_err(|_| ProtocolError::OtherOwned("peer ready auth signature must be exactly 64 bytes".to_string()))?;
                if !verify_node_auth_proof(
                    network_code,
                    &peer_pubkey,
                    &peer_node_id,
                    &self.unified_node_identity.node_id,
                    peer_nonce,
                    local_node_challenge_nonce,
                    &peer_signature,
                ) {
                    return Err(ProtocolError::OtherOwned("peer ready auth signature verification failed".to_string()));
                }
            }

            let peer_has_pq_ready_payload =
                !received_ready_message.pq_ml_kem1024_ciphertext.is_empty() || !received_ready_message.pq_handshake_proof.is_empty();
            if !peer_has_pq_ready_payload {
                if enforce_hardfork_core {
                    return Err(ProtocolError::OtherOwned(
                        "peer missing mandatory quantum-safe ready payload after hardfork".to_string(),
                    ));
                }
            } else {
                if received_ready_message.pq_ml_kem1024_ciphertext.len() != PQ_MLKEM1024_CIPHERTEXT_SIZE {
                    return Err(ProtocolError::OtherOwned(format!(
                        "peer ML-KEM-1024 ciphertext must be exactly {PQ_MLKEM1024_CIPHERTEXT_SIZE} bytes"
                    )));
                }
                if received_ready_message.pq_handshake_proof.len() != PQ_HANDSHAKE_PROOF_SIZE {
                    return Err(ProtocolError::OtherOwned(format!(
                        "peer quantum-safe handshake proof must be exactly {PQ_HANDSHAKE_PROOF_SIZE} bytes"
                    )));
                }

                let peer_shared_secret = decapsulate_mlkem1024(
                    &local_pq_ml_kem1024_private_key,
                    received_ready_message.pq_ml_kem1024_ciphertext.as_slice(),
                )
                .map_err(|err| ProtocolError::OtherOwned(format!("failed decapsulating peer ML-KEM-1024 payload: {err}")))?;
                let expected_peer_proof = compute_pq_handshake_proof(
                    network_code,
                    &peer_node_id,
                    &self.unified_node_identity.node_id,
                    peer_nonce,
                    local_node_challenge_nonce,
                    &peer_shared_secret,
                );
                let peer_proof: [u8; PQ_HANDSHAKE_PROOF_SIZE] =
                    received_ready_message.pq_handshake_proof.as_slice().try_into().map_err(|_| {
                        ProtocolError::OtherOwned(format!(
                            "peer quantum-safe handshake proof must be exactly {PQ_HANDSHAKE_PROOF_SIZE} bytes"
                        ))
                    })?;
                if peer_proof != expected_peer_proof {
                    return Err(ProtocolError::OtherOwned("peer quantum-safe handshake proof verification failed".to_string()));
                }
            }
        }

        info!("Registering p2p flows for peer {} for protocol version {}", router, applied_protocol_version);

        // Launch all flows. Note we launch only after the ready signal was exchanged
        for flow in flows {
            flow.launch();
        }

        let mut address_manager = self.address_manager.lock();

        if router.is_outbound() {
            address_manager.add_verified_address(router.net_address().into());
        }

        if let Some(peer_ip_address) = peer_version.address {
            // Peer-advertised addresses are unauthenticated handshake hints and must not
            // be promoted to verified without an actual successful connection.
            address_manager.add_address(peer_ip_address);
        }

        // Note: we deliberately do not hold the handshake in memory so at this point receivers for handshake subscriptions
        // are dropped, hence effectively unsubscribing from these messages. This means that if the peer re-sends them
        // it is considered a protocol error and the connection will disconnect

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::is_compatible_peer_network;

    #[test]
    fn test_network_compatibility() {
        assert!(is_compatible_peer_network("cryptix-mainnet", "cryptix-mainnet"));
        assert!(is_compatible_peer_network("cryptix-testnet", "cryptix-testnet"));
        assert!(!is_compatible_peer_network("cryptix-testnet", "cryptix-testnet-isolated"));
        assert!(!is_compatible_peer_network("cryptix-testnet-isolated", "cryptix-testnet"));
        assert!(!is_compatible_peer_network("cryptix-mainnet", "cryptix-testnet"));
    }
}
