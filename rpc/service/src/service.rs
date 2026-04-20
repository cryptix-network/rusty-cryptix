//! Core server implementation for ClientAPI

use super::collector::{CollectorFromConsensus, CollectorFromIndex};
use crate::converter::feerate_estimate::{FeeEstimateConverter, FeeEstimateVerboseConverter};
use crate::converter::{consensus::ConsensusConverter, index::IndexConverter, protocol::ProtocolConverter};
use crate::hfa::{FastIngressSource, HfaEngine, HfaRuntimeConfig};
use crate::service::NetworkType::{Mainnet, Testnet};
use async_trait::async_trait;
use blake2b_simd::Params as Blake2bParams;
use cryptix_addresses::Address;
use cryptix_atomicindex::{
    payload::{parse_atomic_token_payload, NoopReason, SupplyMode, TokenOp},
    service::{AtomicTokenService, ScBootstrapSource, ScSnapshotChunk, ScSnapshotManifestSignature},
    state::{AtomicTokenHealth, AtomicTokenReadView, AtomicTokenRuntimeState, ProcessedOp, TokenAsset, TokenEvent},
};
use cryptix_consensus_core::api::counters::ProcessingCounters;
use cryptix_consensus_core::errors::block::RuleError;
use cryptix_consensus_core::{
    blockhash::BlockHashExtensions,
    block::Block,
    coinbase::MinerData,
    config::Config,
    constants::MAX_SOMPI,
    network::NetworkType,
    tx::{ScriptPublicKey, Transaction, COINBASE_TRANSACTION_INDEX},
};
use cryptix_consensus_notify::{
    notifier::ConsensusNotifier,
    {connection::ConsensusChannelConnection, notification::Notification as ConsensusNotification},
};
use cryptix_consensusmanager::ConsensusManager;
use cryptix_core::time::unix_now;
use cryptix_core::{
    core::Core,
    cryptixd_env::version,
    debug, info,
    signals::Shutdown,
    task::service::{AsyncService, AsyncServiceError, AsyncServiceFuture},
    task::tick::TickService,
    trace, warn,
};
use cryptix_index_core::indexed_utxos::BalanceByScriptPublicKey;
use cryptix_index_core::{
    connection::IndexChannelConnection, indexed_utxos::UtxoSetByScriptPublicKey, notification::Notification as IndexNotification,
    notifier::IndexNotifier,
};
use cryptix_mining::feerate::FeeEstimateVerbose;
use cryptix_mining::model::tx_query::TransactionQuery;
use cryptix_mining::{manager::MiningManagerProxy, mempool::tx::Orphan};
use cryptix_notify::listener::ListenerLifespan;
use cryptix_notify::subscription::context::SubscriptionContext;
use cryptix_notify::subscription::{MutationPolicies, UtxosChangedMutationPolicy};
use cryptix_notify::{
    collector::DynCollector,
    connection::ChannelType,
    events::{EventSwitches, EventType, EVENT_TYPE_ARRAY},
    listener::ListenerId,
    notifier::{Notifier, Notify},
    scope::Scope,
    subscriber::{Subscriber, SubscriptionManager},
};
use cryptix_p2p_flows::flow_context::FlowContext;
use cryptix_p2p_flows::hfa::FastIntentP2pData;
use cryptix_p2p_lib::common::ProtocolError;
use cryptix_perf_monitor::{counters::CountersSnapshot, Monitor as PerfMonitor};
use cryptix_rpc_core::{
    api::{
        connection::DynRpcConnection,
        ops::{RPC_API_REVISION, RPC_API_VERSION},
        rpc::{RpcApi, MAX_SAFE_WINDOW_SIZE},
    },
    model::*,
    notify::connection::ChannelConnection,
    Notification, RpcError, RpcResult,
};
use cryptix_txscript::{extract_script_pub_key_address, pay_to_address_script, script_class::ScriptClass};
use cryptix_utils::expiring_cache::ExpiringCache;
use cryptix_utils::hex::{FromHex, ToHex};
use cryptix_utils::sysinfo::SystemInfo;
use cryptix_utils::{channel::Channel, triggers::SingleTrigger};
use cryptix_utils_tower::counters::TowerConnectionCounters;
use cryptix_utxoindex::api::UtxoIndexProxy;
use std::time::Duration;
use std::{
    collections::HashMap,
    iter::once,
    sync::{atomic::Ordering, Arc},
    vec,
};
use tokio::{
    join, select,
    time::{interval, MissedTickBehavior},
};
use workflow_rpc::server::WebSocketCounters as WrpcServerCounters;

/// A service implementing the Rpc API at cryptix_rpc_core level.
///
/// Collects notifications from the consensus and forwards them to
/// actual protocol-featured services. Thanks to the subscription pattern,
/// notifications are sent to the registered services only if the actually
/// need them.
///
/// ### Implementation notes
///
/// This was designed to have a unique instance in the whole application,
/// though multiple instances could coexist safely.
///
/// Any lower-level service providing an actual protocol, like gPRC should
/// register into this instance in order to get notifications. The data flow
/// from this instance to registered services and backwards should occur
/// by adding respectively to the registered service a Collector and a
/// Subscriber.
pub struct RpcCoreService {
    consensus_manager: Arc<ConsensusManager>,
    notifier: Arc<Notifier<Notification, ChannelConnection>>,
    mining_manager: MiningManagerProxy,
    flow_context: Arc<FlowContext>,
    utxoindex: Option<UtxoIndexProxy>,
    atomic_token_service: Arc<AtomicTokenService>,
    config: Arc<Config>,
    consensus_converter: Arc<ConsensusConverter>,
    index_converter: Arc<IndexConverter>,
    protocol_converter: Arc<ProtocolConverter>,
    core: Arc<Core>,
    processing_counters: Arc<ProcessingCounters>,
    wrpc_borsh_counters: Arc<WrpcServerCounters>,
    wrpc_json_counters: Arc<WrpcServerCounters>,
    shutdown: SingleTrigger,
    core_shutdown_request: SingleTrigger,
    perf_monitor: Arc<PerfMonitor<Arc<TickService>>>,
    p2p_tower_counters: Arc<TowerConnectionCounters>,
    grpc_tower_counters: Arc<TowerConnectionCounters>,
    system_info: SystemInfo,
    fee_estimate_cache: ExpiringCache<RpcFeeEstimate>,
    fee_estimate_verbose_cache: ExpiringCache<cryptix_mining::errors::MiningManagerResult<GetFeeEstimateExperimentalResponse>>,
    hfa_engine: Arc<HfaEngine>,
}

const RPC_CORE: &str = "rpc-core";
const NORMAL_POLICY_REJECT_FAST_LOCK_CONFLICT: &str = "normal_policy_reject_fast_lock_conflict";
const HFA_MAINTENANCE_INTERVAL: Duration = Duration::from_millis(100);
const TOKEN_EVENTS_NOTIFY_POLL_INTERVAL: Duration = Duration::from_millis(250);
const TOKEN_EVENTS_LIMIT_MAX: usize = 4096;
const TOKEN_ASSETS_LIMIT_MAX: usize = 2048;
const TOKEN_OWNER_BALANCES_LIMIT_MAX: usize = 4096;
const TOKEN_HOLDERS_LIMIT_MAX: usize = 4096;
const CAT_OWNER_DOMAIN: &[u8] = b"CAT_OWNER_V2";
const OWNER_AUTH_SCHEME_PUBKEY: u8 = 0;
const OWNER_AUTH_SCHEME_PUBKEY_ECDSA: u8 = 1;
const OWNER_AUTH_SCHEME_SCRIPT_HASH: u8 = 2;

impl RpcCoreService {
    pub const IDENT: &'static str = "rpc-core-service";

    fn annotate_transaction_fast_path(&self, transaction: &mut RpcTransaction) {
        let tx_id = transaction
            .verbose_data
            .as_ref()
            .map(|verbose| verbose.transaction_id)
            .or_else(|| Transaction::try_from(transaction.clone()).ok().map(|tx| tx.id()));

        if let Some(tx_id) = tx_id {
            if self.hfa_engine.is_fast_tx_route(tx_id) {
                transaction.fast_path = Some(true);
            }
        }
    }

    fn annotate_block_fast_paths(&self, block: &mut RpcBlock) {
        for transaction in &mut block.transactions {
            self.annotate_transaction_fast_path(transaction);
        }
    }

    fn annotate_mempool_entry_fast_path(&self, entry: &mut RpcMempoolEntry) {
        self.annotate_transaction_fast_path(&mut entry.transaction);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        consensus_manager: Arc<ConsensusManager>,
        consensus_notifier: Arc<ConsensusNotifier>,
        index_notifier: Option<Arc<IndexNotifier>>,
        mining_manager: MiningManagerProxy,
        flow_context: Arc<FlowContext>,
        subscription_context: SubscriptionContext,
        utxoindex: Option<UtxoIndexProxy>,
        atomic_token_service: Arc<AtomicTokenService>,
        config: Arc<Config>,
        core: Arc<Core>,
        processing_counters: Arc<ProcessingCounters>,
        wrpc_borsh_counters: Arc<WrpcServerCounters>,
        wrpc_json_counters: Arc<WrpcServerCounters>,
        perf_monitor: Arc<PerfMonitor<Arc<TickService>>>,
        p2p_tower_counters: Arc<TowerConnectionCounters>,
        grpc_tower_counters: Arc<TowerConnectionCounters>,
        system_info: SystemInfo,
        hfa_config: HfaRuntimeConfig,
    ) -> Self {
        // This notifier UTXOs subscription granularity to index-processor or consensus notifier
        let policies = match index_notifier {
            Some(_) => MutationPolicies::new(UtxosChangedMutationPolicy::AddressSet),
            None => MutationPolicies::new(UtxosChangedMutationPolicy::Wildcard),
        };

        // Prepare consensus-notify objects
        let consensus_notify_channel = Channel::<ConsensusNotification>::default();
        let consensus_notify_listener_id = consensus_notifier.register_new_listener(
            ConsensusChannelConnection::new(RPC_CORE, consensus_notify_channel.sender(), ChannelType::Closable),
            ListenerLifespan::Static(Default::default()),
        );

        // Prepare the rpc-core notifier objects
        let mut consensus_events: EventSwitches = EVENT_TYPE_ARRAY[..].into();
        consensus_events[EventType::UtxosChanged] = false;
        consensus_events[EventType::PruningPointUtxoSetOverride] = index_notifier.is_none();
        let consensus_converter = Arc::new(ConsensusConverter::new(consensus_manager.clone(), config.clone()));
        let consensus_collector = Arc::new(CollectorFromConsensus::new(
            "rpc-core <= consensus",
            consensus_notify_channel.receiver(),
            consensus_converter.clone(),
        ));
        let consensus_subscriber =
            Arc::new(Subscriber::new("rpc-core => consensus", consensus_events, consensus_notifier, consensus_notify_listener_id));

        let mut collectors: Vec<DynCollector<Notification>> = vec![consensus_collector];
        let mut subscribers = vec![consensus_subscriber];

        // Prepare index-processor objects if an IndexService is provided
        let index_converter = Arc::new(IndexConverter::new(config.clone()));
        if let Some(ref index_notifier) = index_notifier {
            let index_notify_channel = Channel::<IndexNotification>::default();
            let index_notify_listener_id = index_notifier.clone().register_new_listener(
                IndexChannelConnection::new(RPC_CORE, index_notify_channel.sender(), ChannelType::Closable),
                ListenerLifespan::Static(policies),
            );

            let index_event_types: &[EventType] = &[EventType::UtxosChanged, EventType::PruningPointUtxoSetOverride];
            let index_events: EventSwitches = index_event_types.into();
            let index_collector =
                Arc::new(CollectorFromIndex::new("rpc-core <= index", index_notify_channel.receiver(), index_converter.clone()));
            let index_subscriber =
                Arc::new(Subscriber::new("rpc-core => index", index_events, index_notifier.clone(), index_notify_listener_id));

            collectors.push(index_collector);
            subscribers.push(index_subscriber);
        }

        // Protocol converter
        let protocol_converter = Arc::new(ProtocolConverter::new(flow_context.clone()));

        // Create the rcp-core notifier
        let notifier =
            Arc::new(Notifier::new(RPC_CORE, EVENT_TYPE_ARRAY[..].into(), collectors, subscribers, subscription_context, 1, policies));

        let hfa_engine = Arc::new(HfaEngine::new(hfa_config));
        flow_context.set_hfa_bridge(hfa_engine.clone());

        Self {
            consensus_manager,
            notifier,
            mining_manager,
            flow_context,
            utxoindex,
            atomic_token_service,
            config,
            consensus_converter,
            index_converter,
            protocol_converter,
            core,
            processing_counters,
            wrpc_borsh_counters,
            wrpc_json_counters,
            shutdown: SingleTrigger::default(),
            core_shutdown_request: SingleTrigger::default(),
            perf_monitor,
            p2p_tower_counters,
            grpc_tower_counters,
            system_info,
            fee_estimate_cache: ExpiringCache::new(Duration::from_millis(500), Duration::from_millis(1000)),
            fee_estimate_verbose_cache: ExpiringCache::new(Duration::from_millis(500), Duration::from_millis(1000)),
            hfa_engine,
        }
    }

    pub fn start_impl(&self) {
        self.notifier().start();

        let token_shutdown_listener = self.shutdown.listener.clone();
        let atomic_token_service = self.atomic_token_service.clone();
        let notifier = self.notifier.clone();
        tokio::spawn(async move {
            let mut tick = interval(TOKEN_EVENTS_NOTIFY_POLL_INTERVAL);
            tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

            let shutdown = token_shutdown_listener;
            tokio::pin!(shutdown);

            let mut last_sequence = atomic_token_service.get_health().await.last_sequence;
            loop {
                select! {
                    _ = &mut shutdown => break,
                    _ = tick.tick() => {
                        let current_sequence = atomic_token_service.get_health().await.last_sequence;
                        if current_sequence > last_sequence {
                            let from_sequence = last_sequence.saturating_add(1);
                            let to_sequence = current_sequence;
                            let delta = current_sequence.saturating_sub(last_sequence);
                            let event_count = delta.min(u64::from(u32::MAX)) as u32;

                            if let Err(err) = notifier.notify(Notification::TokenEventsChanged(TokenEventsChangedNotification {
                                from_sequence,
                                to_sequence,
                                event_count,
                            })) {
                                warn!("failed broadcasting token-events-changed notification: {err}");
                            }
                        }
                        last_sequence = current_sequence;
                    }
                }
            }
        });

        if !self.hfa_engine.is_enabled() {
            return;
        }

        let shutdown_listener = self.shutdown.listener.clone();
        let hfa_engine = self.hfa_engine.clone();
        let flow_context = self.flow_context.clone();
        let consensus_manager = self.consensus_manager.clone();
        let perf_monitor = self.perf_monitor.clone();

        tokio::spawn(async move {
            let mut tick = interval(HFA_MAINTENANCE_INTERVAL);
            tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
            let shutdown = shutdown_listener;
            tokio::pin!(shutdown);

            loop {
                select! {
                    _ = &mut shutdown => break,
                    _ = tick.tick() => {
                        let session = consensus_manager.consensus().unguarded_session();
                        let has_sufficient_peer_connectivity =
                            !matches!(flow_context.config.net.network_type, Mainnet | Testnet) || flow_context.hub().has_peers();
                        let is_synced = has_sufficient_peer_connectivity && session.async_is_nearly_synced().await;
                        let sink_timestamp_ms = session.async_get_sink_timestamp().await;
                        let basechain_block_latency_ms = unix_now().saturating_sub(sink_timestamp_ms) as f64;
                        let cpu_ratio = (perf_monitor.snapshot().cpu_usage as f64 / 100.0).clamp(0.0, 1.0);

                        hfa_engine.revalidate_active_budgeted(session, is_synced, cpu_ratio, basechain_block_latency_ms).await;
                        flow_context.broadcast_outbound_fast_microblocks().await;
                    }
                }
            }
        });
    }

    pub async fn join(&self) -> RpcResult<()> {
        trace!("{} joining notifier", Self::IDENT);
        self.notifier().join().await?;
        Ok(())
    }

    #[inline(always)]
    pub fn notifier(&self) -> Arc<Notifier<Notification, ChannelConnection>> {
        self.notifier.clone()
    }

    #[inline(always)]
    pub fn subscription_context(&self) -> SubscriptionContext {
        self.notifier.subscription_context().clone()
    }

    pub fn core_shutdown_request_listener(&self) -> triggered::Listener {
        self.core_shutdown_request.listener.clone()
    }

    async fn get_utxo_set_by_script_public_key<'a>(
        &self,
        addresses: impl Iterator<Item = &'a RpcAddress>,
    ) -> UtxoSetByScriptPublicKey {
        self.utxoindex
            .clone()
            .unwrap()
            .get_utxos_by_script_public_keys(addresses.map(pay_to_address_script).collect())
            .await
            .unwrap_or_default()
    }

    async fn get_balance_by_script_public_key<'a>(&self, addresses: impl Iterator<Item = &'a RpcAddress>) -> BalanceByScriptPublicKey {
        self.utxoindex
            .clone()
            .unwrap()
            .get_balance_by_script_public_keys(addresses.map(pay_to_address_script).collect())
            .await
            .unwrap_or_default()
    }

    fn has_sufficient_peer_connectivity(&self) -> bool {
        // Other network types can be used in an isolated environment without peers
        !matches!(self.flow_context.config.net.network_type, Mainnet | Testnet) || self.flow_context.hub().has_peers()
    }

    fn atomic_service(&self) -> RpcResult<Arc<AtomicTokenService>> {
        Ok(self.atomic_token_service.clone())
    }

    fn parse_hex_32(value: &str, field: &str) -> RpcResult<[u8; 32]> {
        <[u8; 32]>::from_hex(value).map_err(|err| RpcError::General(format!("invalid `{field}` hex: {err}")))
    }

    fn token_state_unavailable_error(runtime_state: AtomicTokenRuntimeState) -> RpcError {
        match runtime_state {
            AtomicTokenRuntimeState::NotReady => RpcError::AtomicStateNotReady,
            AtomicTokenRuntimeState::Recovering => RpcError::AtomicStateRecovering,
            AtomicTokenRuntimeState::Degraded => RpcError::AtomicStateDegraded,
            AtomicTokenRuntimeState::Healthy => RpcError::General("invalid token runtime state guard".to_string()),
        }
    }

    fn ensure_token_read_ready(view: &AtomicTokenReadView) -> RpcResult<()> {
        match view.runtime_state {
            AtomicTokenRuntimeState::Healthy => Ok(()),
            other => Err(Self::token_state_unavailable_error(other)),
        }
    }

    fn ensure_token_simulation_ready(view: &AtomicTokenReadView) -> RpcResult<()> {
        Self::ensure_token_read_ready(view)
    }

    async fn atomic_context(&self, view: &AtomicTokenReadView) -> RpcResult<RpcTokenContext> {
        let consensus = self.consensus_manager.consensus();
        let session = consensus.session().await;
        let at_block_hash = view.at_block_hash;
        let at_daa_score = session
            .async_get_header(at_block_hash)
            .await
            .map_err(|err| RpcError::General(format!("failed reading token context header: {err}")))?
            .daa_score;
        Ok(RpcTokenContext {
            at_block_hash,
            at_daa_score,
            state_hash: view.state_hash.as_slice().to_hex(),
            is_degraded: view.is_degraded,
        })
    }

    fn map_token_asset(asset: TokenAsset) -> RpcTokenAsset {
        let safe_name = Self::sanitize_token_display_text(&asset.name);
        let safe_symbol = Self::sanitize_token_display_text(&asset.symbol);
        RpcTokenAsset {
            asset_id: asset.asset_id.as_slice().to_hex(),
            creator_owner_id: asset.creator_owner_id.as_slice().to_hex(),
            mint_authority_owner_id: asset.mint_authority_owner_id.as_slice().to_hex(),
            decimals: asset.decimals as u32,
            supply_mode: asset.supply_mode as u32,
            max_supply: asset.max_supply.to_string(),
            total_supply: asset.total_supply.to_string(),
            name: safe_name,
            symbol: safe_symbol,
            metadata_hex: asset.metadata.to_hex(),
            created_block_hash: asset.created_block_hash,
            created_daa_score: asset.created_daa_score,
            created_at: asset.created_at,
        }
    }

    fn map_token_event(event: TokenEvent) -> RpcTokenEvent {
        RpcTokenEvent {
            event_id: event.event_id.as_slice().to_hex(),
            sequence: event.sequence,
            accepting_block_hash: event.accepting_block_hash,
            txid: event.txid,
            event_type: event.event_type as u32,
            apply_status: event.apply_status as u32,
            noop_reason: event.noop_reason as u32,
            ordinal: event.ordinal,
            reorg_of_event_id: event.reorg_of_event_id.map(|id| id.as_slice().to_hex()),
            op_type: event.details.op_type.map(|op| op as u32),
            asset_id: event.details.asset_id.map(|id| id.as_slice().to_hex()),
            from_owner_id: event.details.from_owner_id.map(|id| id.as_slice().to_hex()),
            to_owner_id: event.details.to_owner_id.map(|id| id.as_slice().to_hex()),
            amount: event.details.amount.map(|amount| amount.to_string()),
        }
    }

    fn map_token_owner_balance(entry: ([u8; 32], u128, Option<TokenAsset>)) -> RpcTokenOwnerBalance {
        RpcTokenOwnerBalance {
            asset_id: entry.0.as_slice().to_hex(),
            balance: entry.1.to_string(),
            asset: entry.2.map(Self::map_token_asset),
        }
    }

    fn map_token_holder(entry: ([u8; 32], u128)) -> RpcTokenHolder {
        RpcTokenHolder { owner_id: entry.0.as_slice().to_hex(), balance: entry.1.to_string() }
    }

    fn token_asset_matches_query(asset: &TokenAsset, query: &str) -> bool {
        if query.is_empty() {
            return true;
        }

        let q = query.to_ascii_lowercase();
        let symbol = Self::sanitize_token_display_text(&asset.symbol).to_ascii_lowercase();
        let name = Self::sanitize_token_display_text(&asset.name).to_ascii_lowercase();
        let asset_id = asset.asset_id.as_slice().to_hex();
        symbol.contains(&q) || name.contains(&q) || asset_id.starts_with(&q)
    }

    fn sanitize_token_display_text(bytes: &[u8]) -> String {
        let decoded = String::from_utf8_lossy(bytes);
        let mut out = String::with_capacity(decoded.len());

        for ch in decoded.chars() {
            if ch.is_control()
                || matches!(
                    ch,
                    '\u{202A}' | '\u{202B}' | '\u{202C}' | '\u{202D}' | '\u{202E}' | '\u{2066}' | '\u{2067}' | '\u{2068}' | '\u{2069}'
                )
                || ch == '<'
                || ch == '>'
            {
                out.push(' ');
            } else {
                out.push(ch);
            }
        }

        out.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    fn owner_id_from_script(script_public_key: &ScriptPublicKey) -> Option<[u8; 32]> {
        let script_bytes = script_public_key.script();
        let (auth_scheme, canonical_pubkey_bytes) = match ScriptClass::from_script(script_public_key) {
            ScriptClass::PubKey if script_bytes.len() == 34 => (OWNER_AUTH_SCHEME_PUBKEY, &script_bytes[1..33]),
            ScriptClass::PubKeyECDSA if script_bytes.len() == 35 => (OWNER_AUTH_SCHEME_PUBKEY_ECDSA, &script_bytes[1..34]),
            ScriptClass::ScriptHash if script_bytes.len() == 34 => (OWNER_AUTH_SCHEME_SCRIPT_HASH, &script_bytes[2..34]),
            _ => return None,
        };
        let pubkey_len = u16::try_from(canonical_pubkey_bytes.len()).ok()?;
        let mut hasher = Blake2bParams::new().hash_length(32).to_state();
        hasher.update(CAT_OWNER_DOMAIN);
        hasher.update(&[auth_scheme]);
        hasher.update(&pubkey_len.to_le_bytes());
        hasher.update(canonical_pubkey_bytes);
        let digest = hasher.finalize();
        let mut owner_id = [0u8; 32];
        owner_id.copy_from_slice(digest.as_bytes());
        Some(owner_id)
    }

    fn map_sc_bootstrap_source(source: ScBootstrapSource) -> RpcScBootstrapSource {
        RpcScBootstrapSource {
            snapshot_id: source.snapshot_id,
            protocol_version: source.protocol_version as u32,
            network_id: source.network_id,
            node_identity: source.node_identity.as_slice().to_hex(),
            at_block_hash: source.at_block_hash,
            at_daa_score: source.at_daa_score,
            state_hash_at_fp: source.state_hash_at_fp.as_slice().to_hex(),
            window_start_block_hash: source.window_start_block_hash,
            window_end_block_hash: source.window_end_block_hash,
        }
    }

    fn map_sc_chunk(chunk: ScSnapshotChunk) -> GetScSnapshotChunkResponse {
        GetScSnapshotChunkResponse {
            snapshot_id: chunk.snapshot_id,
            chunk_index: chunk.chunk_index,
            total_chunks: chunk.total_chunks,
            file_size: chunk.file_size,
            chunk_hex: chunk.chunk_data.to_hex(),
        }
    }

    fn map_sc_manifest_signature(signature: ScSnapshotManifestSignature) -> RpcScManifestSignature {
        RpcScManifestSignature {
            signer_pubkey_hex: signature.signer_pubkey.as_slice().to_hex(),
            signature_hex: signature.signature.as_slice().to_hex(),
        }
    }

    fn map_processed_op(op: ProcessedOp, context: RpcTokenContext) -> GetTokenOpStatusResponse {
        GetTokenOpStatusResponse {
            accepting_block_hash: Some(op.accepting_block_hash),
            apply_status: Some(op.apply_status as u32),
            noop_reason: Some(op.noop_reason as u32),
            context,
        }
    }

    fn map_health_response(health: AtomicTokenHealth, context: RpcTokenContext) -> GetTokenHealthResponse {
        GetTokenHealthResponse {
            is_degraded: health.is_degraded,
            bootstrap_in_progress: health.bootstrap_in_progress,
            live_correct: health.live_correct,
            token_state: health.runtime_state.as_str().to_string(),
            last_applied_block: health.last_applied_block,
            last_sequence: health.last_sequence,
            state_hash: health.current_state_hash.as_slice().to_hex(),
            context,
        }
    }

    fn simulate_token_noop_reason(
        &self,
        view: &AtomicTokenReadView,
        owner_id: [u8; 32],
        parsed: &cryptix_atomicindex::payload::ParsedTokenPayload,
    ) -> Option<NoopReason> {
        let expected_next_nonce = view.nonces.get(&owner_id).copied().unwrap_or(1);
        if parsed.header.nonce != expected_next_nonce {
            return Some(NoopReason::BadNonce);
        }

        match &parsed.op {
            TokenOp::CreateAsset(op) => match op.supply_mode {
                SupplyMode::Capped if op.max_supply == 0 => Some(NoopReason::BadMaxSupply),
                SupplyMode::Uncapped if op.max_supply != 0 => Some(NoopReason::BadMaxSupply),
                _ => None,
            },
            TokenOp::Transfer(op) => {
                if !view.assets.contains_key(&op.asset_id) {
                    return Some(NoopReason::AssetNotFound);
                }
                let sender_balance = view
                    .balances
                    .get(&cryptix_atomicindex::state::BalanceKey { asset_id: op.asset_id, owner_id })
                    .copied()
                    .unwrap_or(0);
                if sender_balance < op.amount {
                    return Some(NoopReason::InsufficientBalance);
                }
                let receiver_balance = view
                    .balances
                    .get(&cryptix_atomicindex::state::BalanceKey { asset_id: op.asset_id, owner_id: op.to_owner_id })
                    .copied()
                    .unwrap_or(0);
                if receiver_balance.checked_add(op.amount).is_none() {
                    return Some(NoopReason::BalanceOverflow);
                }
                None
            }
            TokenOp::Mint(op) => {
                let Some(asset) = view.assets.get(&op.asset_id) else {
                    return Some(NoopReason::AssetNotFound);
                };
                if asset.mint_authority_owner_id != owner_id {
                    return Some(NoopReason::UnauthorizedMint);
                }
                let Some(new_total_supply) = asset.total_supply.checked_add(op.amount) else {
                    return Some(NoopReason::SupplyOverflow);
                };
                if matches!(asset.supply_mode, SupplyMode::Capped) && new_total_supply > asset.max_supply {
                    return Some(NoopReason::SupplyCapExceeded);
                }
                let receiver_balance = view
                    .balances
                    .get(&cryptix_atomicindex::state::BalanceKey { asset_id: op.asset_id, owner_id: op.to_owner_id })
                    .copied()
                    .unwrap_or(0);
                if receiver_balance.checked_add(op.amount).is_none() {
                    return Some(NoopReason::BalanceOverflow);
                }
                None
            }
            TokenOp::Burn(op) => {
                let Some(asset) = view.assets.get(&op.asset_id) else {
                    return Some(NoopReason::AssetNotFound);
                };
                let sender_balance = view
                    .balances
                    .get(&cryptix_atomicindex::state::BalanceKey { asset_id: op.asset_id, owner_id })
                    .copied()
                    .unwrap_or(0);
                if sender_balance < op.amount {
                    return Some(NoopReason::InsufficientBalance);
                }
                if asset.total_supply < op.amount {
                    return Some(NoopReason::SupplyUnderflow);
                }
                None
            }
        }
    }

    fn extract_tx_query(&self, filter_transaction_pool: bool, include_orphan_pool: bool) -> RpcResult<TransactionQuery> {
        match (filter_transaction_pool, include_orphan_pool) {
            (true, true) => Ok(TransactionQuery::OrphansOnly),
            // Note that the first `true` indicates *filtering* transactions and the second `false` indicates not including
            // orphan txs -- hence the query would be empty by definition and is thus useless
            (true, false) => Err(RpcError::InconsistentMempoolTxQuery),
            (false, true) => Ok(TransactionQuery::All),
            (false, false) => Ok(TransactionQuery::TransactionsOnly),
        }
    }
}

#[async_trait]
impl RpcApi for RpcCoreService {
    async fn submit_block_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        request: SubmitBlockRequest,
    ) -> RpcResult<SubmitBlockResponse> {
        let session = self.consensus_manager.consensus().unguarded_session();

        // TODO: consider adding an error field to SubmitBlockReport to document both the report and error fields
        let is_synced: bool = self.has_sufficient_peer_connectivity() && session.async_is_nearly_synced().await;

        if !self.config.enable_unsynced_mining && !is_synced {
            // error = "Block not submitted - node is not synced"
            return Ok(SubmitBlockResponse { report: SubmitBlockReport::Reject(SubmitBlockRejectReason::IsInIBD) });
        }

        let try_block: RpcResult<Block> = request.block.try_into();
        if let Err(err) = &try_block {
            trace!("incoming SubmitBlockRequest with block conversion error: {}", err);
            // error = format!("Could not parse block: {0}", err)
            return Ok(SubmitBlockResponse { report: SubmitBlockReport::Reject(SubmitBlockRejectReason::BlockInvalid) });
        }
        let block = try_block?;
        let hash = block.hash();

        if !request.allow_non_daa_blocks {
            let virtual_daa_score = session.get_virtual_daa_score();

            // A simple heuristic check which signals that the mined block is out of date
            // and should not be accepted unless user explicitly requests
            let daa_window_block_duration = self.config.daa_window_duration_in_blocks(virtual_daa_score);
            if virtual_daa_score > daa_window_block_duration && block.header.daa_score < virtual_daa_score - daa_window_block_duration
            {
                // error = format!("Block rejected. Reason: block DAA score {0} is too far behind virtual's DAA score {1}", block.header.daa_score, virtual_daa_score)
                return Ok(SubmitBlockResponse { report: SubmitBlockReport::Reject(SubmitBlockRejectReason::BlockInvalid) });
            }
        }

        trace!("incoming SubmitBlockRequest for block {}", hash);
        match self.flow_context.submit_rpc_block(&session, block.clone()).await {
            Ok(_) => Ok(SubmitBlockResponse { report: SubmitBlockReport::Success }),
            Err(ProtocolError::RuleError(RuleError::BadMerkleRoot(h1, h2))) => {
                warn!(
                    "The RPC submitted block triggered a {} error: {}. 
NOTE: This error usually indicates an RPC conversion error between the node and the miner or a mismatched miner implementation.",
                    stringify!(RuleError::BadMerkleRoot),
                    RuleError::BadMerkleRoot(h1, h2)
                );
                if self.config.net.is_mainnet() {
                    warn!("Printing the full block for debug purposes:\n{:?}", block);
                }
                Ok(SubmitBlockResponse { report: SubmitBlockReport::Reject(SubmitBlockRejectReason::BlockInvalid) })
            }
            Err(err) => {
                warn!(
                    "The RPC submitted block triggered an error: {}\nPrinting the full header for debug purposes:\n{:?}",
                    err, block
                );
                Ok(SubmitBlockResponse { report: SubmitBlockReport::Reject(SubmitBlockRejectReason::BlockInvalid) })
            }
        }
    }

    async fn get_block_template_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        request: GetBlockTemplateRequest,
    ) -> RpcResult<GetBlockTemplateResponse> {
        trace!("incoming GetBlockTemplate request");

        if *self.config.net == NetworkType::Mainnet && !self.config.enable_mainnet_mining {
            return Err(RpcError::General("Mining on mainnet is not supported for initial Rust versions".to_owned()));
        }

        // Make sure the pay address prefix matches the config network type
        if request.pay_address.prefix != self.config.prefix() {
            return Err(cryptix_addresses::AddressError::InvalidPrefix(request.pay_address.prefix.to_string()))?;
        }

        // Build block template
        let script_public_key = cryptix_txscript::pay_to_address_script(&request.pay_address);
        let extra_data = version().as_bytes().iter().chain(once(&(b'/'))).chain(&request.extra_data).cloned().collect::<Vec<_>>();
        let miner_data: MinerData = MinerData::new(script_public_key, extra_data);
        let session = self.consensus_manager.consensus().unguarded_session();
        let block_template = self.mining_manager.clone().get_block_template(&session, miner_data).await?;

        // Check coinbase tx payload length
        if block_template.block.transactions[COINBASE_TRANSACTION_INDEX].payload.len() > self.config.max_coinbase_payload_len {
            return Err(RpcError::CoinbasePayloadLengthAboveMax(self.config.max_coinbase_payload_len));
        }

        let is_nearly_synced =
            self.config.is_nearly_synced(block_template.selected_parent_timestamp, block_template.selected_parent_daa_score);
        Ok(GetBlockTemplateResponse {
            block: block_template.block.into(),
            is_synced: self.has_sufficient_peer_connectivity() && is_nearly_synced,
        })
    }

    async fn get_current_block_color_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        request: GetCurrentBlockColorRequest,
    ) -> RpcResult<GetCurrentBlockColorResponse> {
        let session = self.consensus_manager.consensus().unguarded_session();

        match session.async_get_current_block_color(request.hash).await {
            Some(blue) => Ok(GetCurrentBlockColorResponse { blue }),
            None => Err(RpcError::MergerNotFound(request.hash)),
        }
    }

    async fn get_block_call(&self, _connection: Option<&DynRpcConnection>, request: GetBlockRequest) -> RpcResult<GetBlockResponse> {
        // TODO: test
        let session = self.consensus_manager.consensus().session().await;
        let block = session.async_get_block_even_if_header_only(request.hash).await?;
        let mut rpc_block =
            self.consensus_converter.get_block(&session, &block, request.include_transactions, request.include_transactions).await?;
        self.annotate_block_fast_paths(&mut rpc_block);
        Ok(GetBlockResponse { block: rpc_block })
    }

    async fn submit_fast_intent_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        request: SubmitFastIntentRequest,
    ) -> RpcResult<SubmitFastIntentResponse> {
        let mut request = request;
        let now_ms = unix_now();
        let configured_drift_ms = self.hfa_engine.config().clock_drift_max_ms;
        let drift_ms = now_ms.abs_diff(request.client_created_at_ms);
        if drift_ms > configured_drift_ms {
            warn!(
                "Fastchain RPC clock drift correction: client_created_at_ms={} node_now_ms={} drift={}ms > {}ms, rewriting timestamp to node time",
                request.client_created_at_ms, now_ms, drift_ms, configured_drift_ms
            );
            request.client_created_at_ms = now_ms;
        }
        let request_for_p2p = request.clone();

        let session = self.consensus_manager.consensus().unguarded_session();
        let is_synced = self.has_sufficient_peer_connectivity() && session.async_is_nearly_synced().await;
        let sink_timestamp_ms = session.async_get_sink_timestamp().await;
        let basechain_block_latency_ms = unix_now().saturating_sub(sink_timestamp_ms) as f64;
        let cpu_ratio = (self.perf_monitor.snapshot().cpu_usage as f64 / 100.0).clamp(0.0, 1.0);
        let mut response = self
            .hfa_engine
            .submit_fast_intent(
                &self.config.net.to_string(),
                request,
                session.clone(),
                self.mining_manager.clone(),
                is_synced,
                cpu_ratio,
                basechain_block_latency_ms,
                FastIngressSource::Rpc,
            )
            .await;

        let base_tx_for_normal: Transaction = match request_for_p2p.base_tx.clone().try_into() {
            Ok(tx) => tx,
            Err(_) => {
                self.flow_context.broadcast_outbound_fast_microblocks().await;
                if matches!(response.status, RpcFastIntentStatus::Rejected) && response.reason.as_deref() == Some("invalid_base_tx") {
                    return Ok(response);
                }
                return Err(RpcError::General("submit_fast_intent received an invalid base transaction".to_string()));
            }
        };
        let tx_id = base_tx_for_normal.id();

        let normal_submit_result =
            self.flow_context.submit_rpc_transaction(&session, base_tx_for_normal.clone(), Orphan::Forbidden).await;
        if let Err(err) = normal_submit_result {
            let tx_already_known = self.mining_manager.clone().has_transaction(tx_id, TransactionQuery::All).await
                || self.mining_manager.clone().has_accepted_transaction(tx_id).await;
            if !tx_already_known {
                if let Some(cancel_token) = response.cancel_token.clone() {
                    let _ = self.hfa_engine.cancel_fast_intent(CancelFastIntentRequest {
                        intent_id: response.intent_id,
                        cancel_token,
                        node_epoch: response.node_epoch,
                    });
                }
                return Err(RpcError::RejectedTransaction(tx_id, err.to_string()));
            }
        }
        response.basechain_submitted = true;
        if matches!(response.status, RpcFastIntentStatus::Locked | RpcFastIntentStatus::FastConfirmed) && response.reason.is_none() {
            self.hfa_engine.mark_fast_tx_route(tx_id);
        }

        let should_broadcast_fast_intent = response.reason.is_none()
            && matches!(response.status, RpcFastIntentStatus::Locked | RpcFastIntentStatus::FastConfirmed)
            && self.hfa_engine.should_broadcast_intent_once(response.intent_id);

        if should_broadcast_fast_intent {
            self.processing_counters.fast_txs_counts.fetch_add(1, Ordering::Relaxed);
            info!(
                "Fastchain send accepted: intent {} tx {} status={:?} basechain_submitted=true",
                response.intent_id, tx_id, response.status
            );
            self.flow_context
                .broadcast_fast_intent(&FastIntentP2pData {
                    intent_id: response.intent_id,
                    base_tx: base_tx_for_normal,
                    intent_nonce: request_for_p2p.intent_nonce,
                    client_created_at_ms: request_for_p2p.client_created_at_ms,
                    max_fee: request_for_p2p.max_fee,
                })
                .await;
        } else {
            info!(
                "Fastchain send not activated: intent {} tx {} status={:?} reason={:?} basechain_submitted={}",
                response.intent_id, tx_id, response.status, response.reason, response.basechain_submitted
            );
        }
        self.flow_context.broadcast_outbound_fast_microblocks().await;
        Ok(response)
    }

    async fn get_fast_intent_status_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        request: GetFastIntentStatusRequest,
    ) -> RpcResult<GetFastIntentStatusResponse> {
        let session = self.consensus_manager.consensus().unguarded_session();
        let is_synced = self.has_sufficient_peer_connectivity() && session.async_is_nearly_synced().await;
        let sink_timestamp_ms = session.async_get_sink_timestamp().await;
        let basechain_block_latency_ms = unix_now().saturating_sub(sink_timestamp_ms) as f64;
        let cpu_ratio = (self.perf_monitor.snapshot().cpu_usage as f64 / 100.0).clamp(0.0, 1.0);
        self.hfa_engine.revalidate_active_budgeted(session, is_synced, cpu_ratio, basechain_block_latency_ms).await;
        let response = self.hfa_engine.get_fast_intent_status(request);
        self.flow_context.broadcast_outbound_fast_microblocks().await;
        Ok(response)
    }

    async fn cancel_fast_intent_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        request: CancelFastIntentRequest,
    ) -> RpcResult<CancelFastIntentResponse> {
        let session = self.consensus_manager.consensus().unguarded_session();
        let is_synced = self.has_sufficient_peer_connectivity() && session.async_is_nearly_synced().await;
        let sink_timestamp_ms = session.async_get_sink_timestamp().await;
        let basechain_block_latency_ms = unix_now().saturating_sub(sink_timestamp_ms) as f64;
        let cpu_ratio = (self.perf_monitor.snapshot().cpu_usage as f64 / 100.0).clamp(0.0, 1.0);
        self.hfa_engine.revalidate_active_budgeted(session, is_synced, cpu_ratio, basechain_block_latency_ms).await;
        let response = self.hfa_engine.cancel_fast_intent(request);
        self.flow_context.broadcast_outbound_fast_microblocks().await;
        Ok(response)
    }

    async fn get_blocks_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        request: GetBlocksRequest,
    ) -> RpcResult<GetBlocksResponse> {
        // Validate that user didn't set include_transactions without setting include_blocks
        if !request.include_blocks && request.include_transactions {
            return Err(RpcError::InvalidGetBlocksRequest);
        }

        let session = self.consensus_manager.consensus().session().await;

        // If low_hash is empty - use genesis instead.
        let low_hash = match request.low_hash {
            Some(low_hash) => {
                // Make sure low_hash points to an existing and valid block
                session.async_get_ghostdag_data(low_hash).await?;
                low_hash
            }
            None => self.config.genesis.hash,
        };

        // Get hashes between low_hash and sink
        let sink_hash = session.async_get_sink().await;

        // We use +1 because low_hash is also returned
        // max_blocks MUST be >= mergeset_size_limit + 1
        let max_blocks = self.config.mergeset_size_limit as usize + 1;
        let (block_hashes, high_hash) = session.async_get_hashes_between(low_hash, sink_hash, max_blocks).await?;

        // If the high hash is equal to sink it means get_hashes_between didn't skip any hashes, and
        // there's space to add the sink anticone, otherwise we cannot add the anticone because
        // there's no guarantee that all of the anticone root ancestors will be present.
        let sink_anticone = if high_hash == sink_hash { session.async_get_anticone(sink_hash).await? } else { vec![] };
        // Prepend low hash to make it inclusive and append the sink anticone
        let block_hashes = once(low_hash).chain(block_hashes).chain(sink_anticone).collect::<Vec<_>>();
        let blocks = if request.include_blocks {
            let mut blocks = Vec::with_capacity(block_hashes.len());
            for hash in block_hashes.iter().copied() {
                let block = session.async_get_block_even_if_header_only(hash).await?;
                let mut rpc_block = self
                    .consensus_converter
                    .get_block(&session, &block, request.include_transactions, request.include_transactions)
                    .await?;
                self.annotate_block_fast_paths(&mut rpc_block);
                blocks.push(rpc_block)
            }
            blocks
        } else {
            Vec::new()
        };
        Ok(GetBlocksResponse { block_hashes, blocks })
    }

    async fn get_info_call(&self, _connection: Option<&DynRpcConnection>, _request: GetInfoRequest) -> RpcResult<GetInfoResponse> {
        let is_nearly_synced = self.consensus_manager.consensus().unguarded_session().async_is_nearly_synced().await;
        Ok(GetInfoResponse {
            p2p_id: self.flow_context.node_id.to_string(),
            mempool_size: self.mining_manager.transaction_count_sample(TransactionQuery::TransactionsOnly),
            server_version: version().to_string(),
            is_utxo_indexed: self.config.utxoindex,
            is_synced: self.has_sufficient_peer_connectivity() && is_nearly_synced,
            has_notify_command: true,
            has_message_id: true,
        })
    }

    async fn get_mempool_entry_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        request: GetMempoolEntryRequest,
    ) -> RpcResult<GetMempoolEntryResponse> {
        let query = self.extract_tx_query(request.filter_transaction_pool, request.include_orphan_pool)?;
        let Some(transaction) = self.mining_manager.clone().get_transaction(request.transaction_id, query).await else {
            return Err(RpcError::TransactionNotFound(request.transaction_id));
        };
        let session = self.consensus_manager.consensus().unguarded_session();
        let mut entry = self.consensus_converter.get_mempool_entry(&session, &transaction);
        self.annotate_mempool_entry_fast_path(&mut entry);
        Ok(GetMempoolEntryResponse::new(entry))
    }

    async fn get_mempool_entries_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        request: GetMempoolEntriesRequest,
    ) -> RpcResult<GetMempoolEntriesResponse> {
        let query = self.extract_tx_query(request.filter_transaction_pool, request.include_orphan_pool)?;
        let session = self.consensus_manager.consensus().unguarded_session();
        let (transactions, orphans) = self.mining_manager.clone().get_all_transactions(query).await;
        let mut mempool_entries = transactions
            .iter()
            .chain(orphans.iter())
            .map(|transaction| self.consensus_converter.get_mempool_entry(&session, transaction))
            .collect::<Vec<_>>();
        for entry in &mut mempool_entries {
            self.annotate_mempool_entry_fast_path(entry);
        }
        Ok(GetMempoolEntriesResponse::new(mempool_entries))
    }

    async fn get_mempool_entries_by_addresses_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        request: GetMempoolEntriesByAddressesRequest,
    ) -> RpcResult<GetMempoolEntriesByAddressesResponse> {
        let query = self.extract_tx_query(request.filter_transaction_pool, request.include_orphan_pool)?;
        let session = self.consensus_manager.consensus().unguarded_session();
        let script_public_keys = request.addresses.iter().map(pay_to_address_script).collect();
        let grouped_txs = self.mining_manager.clone().get_transactions_by_addresses(script_public_keys, query).await;
        let mut mempool_entries = grouped_txs
            .owners
            .iter()
            .map(|(script_public_key, owner_transactions)| {
                let address = extract_script_pub_key_address(script_public_key, self.config.prefix())
                    .expect("script public key is convertible into an address");
                self.consensus_converter.get_mempool_entries_by_address(
                    &session,
                    address,
                    owner_transactions,
                    &grouped_txs.transactions,
                )
            })
            .collect::<Vec<_>>();
        for owner_entry in &mut mempool_entries {
            for tx in &mut owner_entry.sending {
                self.annotate_mempool_entry_fast_path(tx);
            }
            for tx in &mut owner_entry.receiving {
                self.annotate_mempool_entry_fast_path(tx);
            }
        }
        Ok(GetMempoolEntriesByAddressesResponse::new(mempool_entries))
    }

    async fn submit_transaction_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        request: SubmitTransactionRequest,
    ) -> RpcResult<SubmitTransactionResponse> {
        let allow_orphan = self.config.unsafe_rpc && request.allow_orphan;
        if !self.config.unsafe_rpc && request.allow_orphan {
            debug!("SubmitTransaction RPC command called with AllowOrphan enabled while node in safe RPC mode -- switching to ForbidOrphan.");
        }

        let transaction: Transaction = request.transaction.try_into()?;
        let transaction_id = transaction.id();
        let session = self.consensus_manager.consensus().unguarded_session();
        if self.hfa_engine.has_fast_lock_conflict_for_tx(&transaction) {
            let err = RpcError::RejectedTransaction(transaction_id, NORMAL_POLICY_REJECT_FAST_LOCK_CONFLICT.to_string());
            debug!("{err}");
            return Err(err);
        }
        let orphan = match allow_orphan {
            true => Orphan::Allowed,
            false => Orphan::Forbidden,
        };
        self.flow_context.submit_rpc_transaction(&session, transaction, orphan).await.map_err(|err| {
            let err = RpcError::RejectedTransaction(transaction_id, err.to_string());
            debug!("{err}");
            err
        })?;
        Ok(SubmitTransactionResponse::new(transaction_id))
    }

    async fn submit_transaction_replacement_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        request: SubmitTransactionReplacementRequest,
    ) -> RpcResult<SubmitTransactionReplacementResponse> {
        let transaction: Transaction = request.transaction.try_into()?;
        let transaction_id = transaction.id();
        let session = self.consensus_manager.consensus().unguarded_session();
        if self.hfa_engine.has_fast_lock_conflict_for_tx(&transaction) {
            let err = RpcError::RejectedTransaction(transaction_id, NORMAL_POLICY_REJECT_FAST_LOCK_CONFLICT.to_string());
            debug!("{err}");
            return Err(err);
        }
        let replaced_transaction =
            self.flow_context.submit_rpc_transaction_replacement(&session, transaction).await.map_err(|err| {
                let err = RpcError::RejectedTransaction(transaction_id, err.to_string());
                debug!("{err}");
                err
            })?;
        Ok(SubmitTransactionReplacementResponse::new(transaction_id, (&*replaced_transaction).into()))
    }

    async fn get_current_network_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _: GetCurrentNetworkRequest,
    ) -> RpcResult<GetCurrentNetworkResponse> {
        Ok(GetCurrentNetworkResponse::new(*self.config.net))
    }

    async fn get_subnetwork_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _: GetSubnetworkRequest,
    ) -> RpcResult<GetSubnetworkResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn get_sink_call(&self, _connection: Option<&DynRpcConnection>, _: GetSinkRequest) -> RpcResult<GetSinkResponse> {
        Ok(GetSinkResponse::new(self.consensus_manager.consensus().unguarded_session().async_get_sink().await))
    }

    async fn get_sink_blue_score_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _: GetSinkBlueScoreRequest,
    ) -> RpcResult<GetSinkBlueScoreResponse> {
        let session = self.consensus_manager.consensus().unguarded_session();
        Ok(GetSinkBlueScoreResponse::new(session.async_get_ghostdag_data(session.async_get_sink().await).await?.blue_score))
    }

    async fn get_virtual_chain_from_block_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        request: GetVirtualChainFromBlockRequest,
    ) -> RpcResult<GetVirtualChainFromBlockResponse> {
        let session = self.consensus_manager.consensus().session().await;

        // batch_size is set to 10 times the mergeset_size_limit.
        // this means batch_size is 2480 on 10 bps, and 1800 on mainnet.
        // this bounds by number of merged blocks, if include_accepted_transactions = true
        // else it returns the batch_size amount on pure chain blocks.
        // Note: batch_size does not bound removed chain blocks, only added chain blocks.
        let batch_size = (self.config.mergeset_size_limit * 10) as usize;
        let mut virtual_chain_batch = session.async_get_virtual_chain_from_block(request.start_hash, Some(batch_size)).await?;
        let accepted_transaction_ids = if request.include_accepted_transaction_ids {
            let accepted_transaction_ids = self
                .consensus_converter
                .get_virtual_chain_accepted_transaction_ids(&session, &virtual_chain_batch, Some(batch_size))
                .await?;
            // bound added to the length of the accepted transaction ids, which is bounded by merged blocks
            virtual_chain_batch.added.truncate(accepted_transaction_ids.len());
            accepted_transaction_ids
        } else {
            vec![]
        };
        Ok(GetVirtualChainFromBlockResponse::new(virtual_chain_batch.removed, virtual_chain_batch.added, accepted_transaction_ids))
    }

    async fn get_block_count_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _: GetBlockCountRequest,
    ) -> RpcResult<GetBlockCountResponse> {
        Ok(self.consensus_manager.consensus().unguarded_session().async_estimate_block_count().await)
    }

    async fn get_utxos_by_addresses_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        request: GetUtxosByAddressesRequest,
    ) -> RpcResult<GetUtxosByAddressesResponse> {
        if !self.config.utxoindex {
            return Err(RpcError::NoUtxoIndex);
        }
        // TODO: discuss if the entry order is part of the method requirements
        //       (the current impl does not retain an entry order matching the request addresses order)
        let entry_map = self.get_utxo_set_by_script_public_key(request.addresses.iter()).await;
        Ok(GetUtxosByAddressesResponse::new(self.index_converter.get_utxos_by_addresses_entries(&entry_map)))
    }

    async fn get_balance_by_address_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        request: GetBalanceByAddressRequest,
    ) -> RpcResult<GetBalanceByAddressResponse> {
        if !self.config.utxoindex {
            return Err(RpcError::NoUtxoIndex);
        }
        let entry_map = self.get_balance_by_script_public_key(once(&request.address)).await;
        let balance = entry_map.values().sum();
        Ok(GetBalanceByAddressResponse::new(balance))
    }

    async fn get_balances_by_addresses_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        request: GetBalancesByAddressesRequest,
    ) -> RpcResult<GetBalancesByAddressesResponse> {
        if !self.config.utxoindex {
            return Err(RpcError::NoUtxoIndex);
        }
        let entry_map = self.get_balance_by_script_public_key(request.addresses.iter()).await;
        let entries = request
            .addresses
            .iter()
            .map(|address| {
                let script_public_key = pay_to_address_script(address);
                let balance = entry_map.get(&script_public_key).copied();
                RpcBalancesByAddressesEntry { address: address.to_owned(), balance }
            })
            .collect();
        Ok(GetBalancesByAddressesResponse::new(entries))
    }

    async fn get_coin_supply_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _: GetCoinSupplyRequest,
    ) -> RpcResult<GetCoinSupplyResponse> {
        if !self.config.utxoindex {
            return Err(RpcError::NoUtxoIndex);
        }
        let circulating_sompi =
            self.utxoindex.clone().unwrap().get_circulating_supply().await.map_err(|e| RpcError::General(e.to_string()))?;
        Ok(GetCoinSupplyResponse::new(MAX_SOMPI, circulating_sompi))
    }

    async fn get_daa_score_timestamp_estimate_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        request: GetDaaScoreTimestampEstimateRequest,
    ) -> RpcResult<GetDaaScoreTimestampEstimateResponse> {
        let session = self.consensus_manager.consensus().session().await;
        // TODO: cache samples based on sufficient recency of the data and append sink data
        let mut headers = session.async_get_chain_block_samples().await;
        let mut requested_daa_scores = request.daa_scores.clone();
        let mut daa_score_timestamp_map = HashMap::<u64, u64>::new();

        headers.reverse();
        requested_daa_scores.sort_by(|a, b| b.cmp(a));

        let mut header_idx = 0;
        let mut req_idx = 0;

        // Loop runs at O(n + m) where n = # pp headers, m = # requested daa_scores
        // Loop will always end because in the worst case the last header with daa_score = 0 (the genesis)
        // will cause every remaining requested daa_score to be "found in range"
        //
        // TODO: optimize using binary search over the samples to obtain O(m log n) complexity (which is an improvement assuming m << n)
        while header_idx < headers.len() && req_idx < request.daa_scores.len() {
            let header = headers.get(header_idx).unwrap();
            let curr_daa_score = requested_daa_scores[req_idx];

            // Found daa_score in range
            if header.daa_score <= curr_daa_score {
                // For daa_score later than the last header, we estimate in milliseconds based on the difference
                let time_adjustment = if header_idx == 0 {
                    // estimate milliseconds = (daa_score * target_time_per_block)
                    (curr_daa_score - header.daa_score).checked_mul(self.config.target_time_per_block).unwrap_or(u64::MAX)
                } else {
                    // "next" header is the one that we processed last iteration
                    let next_header = &headers[header_idx - 1];
                    // Unlike DAA scores which are monotonic (over the selected chain), timestamps are not strictly monotonic, so we avoid assuming so
                    let time_between_headers = next_header.timestamp.checked_sub(header.timestamp).unwrap_or_default();
                    let score_between_query_and_header = (curr_daa_score - header.daa_score) as f64;
                    let score_between_headers = (next_header.daa_score - header.daa_score) as f64;
                    // Interpolate the timestamp delta using the estimated fraction based on DAA scores
                    ((time_between_headers as f64) * (score_between_query_and_header / score_between_headers)) as u64
                };

                let daa_score_timestamp = header.timestamp.checked_add(time_adjustment).unwrap_or(u64::MAX);
                daa_score_timestamp_map.insert(curr_daa_score, daa_score_timestamp);

                // Process the next daa score that's <= than current one (at earlier idx)
                req_idx += 1;
            } else {
                header_idx += 1;
            }
        }

        // Note: it is safe to assume all entries exist in the map since the first sampled header is expected to have daa_score=0
        let timestamps = request.daa_scores.iter().map(|curr_daa_score| daa_score_timestamp_map[curr_daa_score]).collect();

        Ok(GetDaaScoreTimestampEstimateResponse::new(timestamps))
    }

    async fn get_fee_estimate_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetFeeEstimateRequest,
    ) -> RpcResult<GetFeeEstimateResponse> {
        let mining_manager = self.mining_manager.clone();
        let estimate =
            self.fee_estimate_cache.get(async move { mining_manager.get_realtime_feerate_estimations().await.into_rpc() }).await;
        Ok(GetFeeEstimateResponse { estimate })
    }

    async fn get_fee_estimate_experimental_call(
        &self,
        connection: Option<&DynRpcConnection>,
        request: GetFeeEstimateExperimentalRequest,
    ) -> RpcResult<GetFeeEstimateExperimentalResponse> {
        if request.verbose {
            let mining_manager = self.mining_manager.clone();
            let consensus_manager = self.consensus_manager.clone();
            let prefix = self.config.prefix();

            let mut response = self
                .fee_estimate_verbose_cache
                .get(async move {
                    let session = consensus_manager.consensus().unguarded_session();
                    mining_manager.get_realtime_feerate_estimations_verbose(&session, prefix).await.map(FeeEstimateVerbose::into_rpc)
                })
                .await?;

            if let Some(verbose) = response.verbose.as_mut() {
                let minimum_relay_feerate = self.mining_manager.clone().minimum_relay_feerate().await.max(0.0);
                let payload_overcap_feerate_floor = self.mining_manager.clone().payload_overcap_feerate_floor().await.max(0.0);
                let effective_hfa_feerate_floor = self.hfa_engine.effective_feerate_floor(minimum_relay_feerate);
                verbose.minimum_relay_feerate = Some(minimum_relay_feerate);
                verbose.payload_overcap_feerate_floor = Some(payload_overcap_feerate_floor);
                verbose.effective_hfa_feerate_floor = Some(effective_hfa_feerate_floor);
            }
            Ok(response)
        } else {
            let estimate = self.get_fee_estimate_call(connection, GetFeeEstimateRequest {}).await?.estimate;
            Ok(GetFeeEstimateExperimentalResponse { estimate, verbose: None })
        }
    }

    async fn ping_call(&self, _connection: Option<&DynRpcConnection>, _: PingRequest) -> RpcResult<PingResponse> {
        Ok(PingResponse {})
    }

    async fn get_headers_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        request: GetHeadersRequest,
    ) -> RpcResult<GetHeadersResponse> {
        if request.limit == 0 {
            return Ok(GetHeadersResponse { headers: vec![] });
        }

        let session = self.consensus_manager.consensus().session().await;
        let limit = request.limit as usize;
        let mut header_hashes = Vec::with_capacity(limit);

        if request.is_ascending {
            header_hashes.push(request.start_hash);

            if limit > 1 {
                let chain_path =
                    session.async_get_virtual_chain_from_block(request.start_hash, Some(limit.saturating_sub(1))).await?;
                header_hashes.extend(chain_path.added);
            }
        } else {
            let mut current = request.start_hash;
            for _ in 0..limit {
                header_hashes.push(current);

                let ghostdag = session.async_get_ghostdag_data(current).await?;
                if ghostdag.selected_parent.is_origin() {
                    break;
                }
                current = ghostdag.selected_parent;
            }
        }

        let mut headers = Vec::with_capacity(header_hashes.len());
        for hash in header_hashes.into_iter() {
            let header = session.async_get_header(hash).await?;
            headers.push((&*header).into());
        }

        Ok(GetHeadersResponse { headers })
    }

    async fn get_block_dag_info_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _: GetBlockDagInfoRequest,
    ) -> RpcResult<GetBlockDagInfoResponse> {
        let session = self.consensus_manager.consensus().unguarded_session();
        let (consensus_stats, tips, pruning_point, sink) =
            join!(session.async_get_stats(), session.async_get_tips(), session.async_pruning_point(), session.async_get_sink());
        Ok(GetBlockDagInfoResponse::new(
            self.config.net,
            consensus_stats.block_counts.block_count,
            consensus_stats.block_counts.header_count,
            tips,
            self.consensus_converter.get_difficulty_ratio(consensus_stats.virtual_stats.bits),
            consensus_stats.virtual_stats.past_median_time,
            session.get_virtual_parents().into_iter().collect::<Vec<_>>(),
            pruning_point,
            consensus_stats.virtual_stats.daa_score,
            sink,
        ))
    }

    async fn estimate_network_hashes_per_second_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        request: EstimateNetworkHashesPerSecondRequest,
    ) -> RpcResult<EstimateNetworkHashesPerSecondResponse> {
        if !self.config.unsafe_rpc && request.window_size > MAX_SAFE_WINDOW_SIZE {
            return Err(RpcError::WindowSizeExceedingMaximum(request.window_size, MAX_SAFE_WINDOW_SIZE));
        }
        if request.window_size as u64 > self.config.pruning_depth {
            return Err(RpcError::WindowSizeExceedingPruningDepth(request.window_size, self.config.pruning_depth));
        }

        // In the previous golang implementation the convention for virtual was the following const.
        // In the current implementation, consensus behaves the same when it gets a None instead.
        const LEGACY_VIRTUAL: cryptix_hashes::Hash = cryptix_hashes::Hash::from_bytes([0xff; cryptix_hashes::HASH_SIZE]);
        let mut start_hash = request.start_hash;
        if let Some(start) = start_hash {
            if start == LEGACY_VIRTUAL {
                start_hash = None;
            }
        }

        Ok(EstimateNetworkHashesPerSecondResponse::new(
            self.consensus_manager
                .consensus()
                .session()
                .await
                .async_estimate_network_hashes_per_second(start_hash, request.window_size as usize)
                .await?,
        ))
    }

    async fn add_peer_call(&self, _connection: Option<&DynRpcConnection>, request: AddPeerRequest) -> RpcResult<AddPeerResponse> {
        if !self.config.unsafe_rpc {
            warn!("AddPeer RPC command called while node in safe RPC mode -- ignoring.");
            return Err(RpcError::UnavailableInSafeMode);
        }
        let peer_address = request.peer_address.normalize(self.config.net.default_p2p_port());
        if let Some(connection_manager) = self.flow_context.connection_manager() {
            connection_manager.add_connection_request(peer_address.into(), request.is_permanent).await;
        } else {
            return Err(RpcError::NoConnectionManager);
        }
        Ok(AddPeerResponse {})
    }

    async fn get_peer_addresses_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _: GetPeerAddressesRequest,
    ) -> RpcResult<GetPeerAddressesResponse> {
        let address_manager = self.flow_context.address_manager.lock();
        Ok(GetPeerAddressesResponse::new(address_manager.get_all_addresses(), address_manager.get_all_banned_addresses()))
    }

    async fn ban_call(&self, _connection: Option<&DynRpcConnection>, request: BanRequest) -> RpcResult<BanResponse> {
        if !self.config.unsafe_rpc {
            warn!("Ban RPC command called while node in safe RPC mode -- ignoring.");
            return Err(RpcError::UnavailableInSafeMode);
        }
        if let Some(connection_manager) = self.flow_context.connection_manager() {
            let ip = request.ip.into();
            if connection_manager.ip_has_permanent_connection(ip).await {
                return Err(RpcError::IpHasPermanentConnection(request.ip));
            }
            connection_manager.ban(ip).await;
        } else {
            return Err(RpcError::NoConnectionManager);
        }
        Ok(BanResponse {})
    }

    async fn unban_call(&self, _connection: Option<&DynRpcConnection>, request: UnbanRequest) -> RpcResult<UnbanResponse> {
        if !self.config.unsafe_rpc {
            warn!("Unban RPC command called while node in safe RPC mode -- ignoring.");
            return Err(RpcError::UnavailableInSafeMode);
        }
        let mut address_manager = self.flow_context.address_manager.lock();
        if address_manager.is_banned(request.ip) {
            address_manager.unban(request.ip)
        } else {
            return Err(RpcError::IpIsNotBanned(request.ip));
        }
        Ok(UnbanResponse {})
    }

    async fn get_connected_peer_info_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _: GetConnectedPeerInfoRequest,
    ) -> RpcResult<GetConnectedPeerInfoResponse> {
        let peers = self.flow_context.hub().active_peers();
        let peer_info = self.protocol_converter.get_peers_info(&peers);
        Ok(GetConnectedPeerInfoResponse::new(peer_info))
    }

    async fn shutdown_call(&self, _connection: Option<&DynRpcConnection>, _: ShutdownRequest) -> RpcResult<ShutdownResponse> {
        if !self.config.unsafe_rpc {
            warn!("Shutdown RPC command called while node in safe RPC mode -- ignoring.");
            return Err(RpcError::UnavailableInSafeMode);
        }
        warn!("Shutdown RPC command was called, shutting down in 1 second...");

        // Signal the shutdown request
        self.core_shutdown_request.trigger.trigger();

        // Wait for a second before shutting down,
        // giving time for the response to be sent to the caller.
        let core = self.core.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            core.shutdown();
        });

        Ok(ShutdownResponse {})
    }

    async fn resolve_finality_conflict_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: ResolveFinalityConflictRequest,
    ) -> RpcResult<ResolveFinalityConflictResponse> {
        if !self.config.unsafe_rpc {
            warn!("ResolveFinalityConflict RPC command called while node in safe RPC mode -- ignoring.");
            return Err(RpcError::UnavailableInSafeMode);
        }
        Err(RpcError::NotImplemented)
    }

    async fn get_connections_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        req: GetConnectionsRequest,
    ) -> RpcResult<GetConnectionsResponse> {
        let clients = (self.wrpc_borsh_counters.active_connections.load(Ordering::Relaxed)
            + self.wrpc_json_counters.active_connections.load(Ordering::Relaxed)) as u32;
        let peers = self.flow_context.hub().active_peers_len() as u16;

        let profile_data = req.include_profile_data.then(|| {
            let CountersSnapshot { resident_set_size: memory_usage, cpu_usage, .. } = self.perf_monitor.snapshot();

            ConnectionsProfileData { cpu_usage: cpu_usage as f32, memory_usage }
        });

        Ok(GetConnectionsResponse { clients, peers, profile_data })
    }

    async fn get_metrics_call(&self, _connection: Option<&DynRpcConnection>, req: GetMetricsRequest) -> RpcResult<GetMetricsResponse> {
        let CountersSnapshot {
            resident_set_size,
            virtual_memory_size,
            core_num,
            cpu_usage,
            fd_num,
            disk_io_read_bytes,
            disk_io_write_bytes,
            disk_io_read_per_sec,
            disk_io_write_per_sec,
        } = self.perf_monitor.snapshot();

        let process_metrics = req.process_metrics.then_some(ProcessMetrics {
            resident_set_size,
            virtual_memory_size,
            core_num: core_num as u32,
            cpu_usage: cpu_usage as f32,
            fd_num: fd_num as u32,
            disk_io_read_bytes,
            disk_io_write_bytes,
            disk_io_read_per_sec: disk_io_read_per_sec as f32,
            disk_io_write_per_sec: disk_io_write_per_sec as f32,
        });

        let connection_metrics = req.connection_metrics.then(|| ConnectionMetrics {
            borsh_live_connections: self.wrpc_borsh_counters.active_connections.load(Ordering::Relaxed) as u32,
            borsh_connection_attempts: self.wrpc_borsh_counters.total_connections.load(Ordering::Relaxed) as u64,
            borsh_handshake_failures: self.wrpc_borsh_counters.handshake_failures.load(Ordering::Relaxed) as u64,
            json_live_connections: self.wrpc_json_counters.active_connections.load(Ordering::Relaxed) as u32,
            json_connection_attempts: self.wrpc_json_counters.total_connections.load(Ordering::Relaxed) as u64,
            json_handshake_failures: self.wrpc_json_counters.handshake_failures.load(Ordering::Relaxed) as u64,

            active_peers: self.flow_context.hub().active_peers_len() as u32,
        });

        let bandwidth_metrics = req.bandwidth_metrics.then(|| BandwidthMetrics {
            borsh_bytes_tx: self.wrpc_borsh_counters.tx_bytes.load(Ordering::Relaxed) as u64,
            borsh_bytes_rx: self.wrpc_borsh_counters.rx_bytes.load(Ordering::Relaxed) as u64,
            json_bytes_tx: self.wrpc_json_counters.tx_bytes.load(Ordering::Relaxed) as u64,
            json_bytes_rx: self.wrpc_json_counters.rx_bytes.load(Ordering::Relaxed) as u64,
            p2p_bytes_tx: self.p2p_tower_counters.bytes_tx.load(Ordering::Relaxed) as u64,
            p2p_bytes_rx: self.p2p_tower_counters.bytes_rx.load(Ordering::Relaxed) as u64,
            grpc_bytes_tx: self.grpc_tower_counters.bytes_tx.load(Ordering::Relaxed) as u64,
            grpc_bytes_rx: self.grpc_tower_counters.bytes_rx.load(Ordering::Relaxed) as u64,
        });

        let consensus_metrics = if req.consensus_metrics {
            let consensus_stats = self.consensus_manager.consensus().unguarded_session().async_get_stats().await;
            let processing_counters = self.processing_counters.snapshot();

            Some(ConsensusMetrics {
                node_blocks_submitted_count: processing_counters.blocks_submitted,
                node_headers_processed_count: processing_counters.header_counts,
                node_dependencies_processed_count: processing_counters.dep_counts,
                node_bodies_processed_count: processing_counters.body_counts,
                node_transactions_processed_count: processing_counters.txs_counts,
                node_chain_blocks_processed_count: processing_counters.chain_block_counts,
                node_mass_processed_count: processing_counters.mass_counts,
                // ---
                node_database_blocks_count: consensus_stats.block_counts.block_count,
                node_database_headers_count: consensus_stats.block_counts.header_count,
                // ---
                network_mempool_size: self.mining_manager.transaction_count_sample(TransactionQuery::TransactionsOnly),
                network_tip_hashes_count: consensus_stats.num_tips.try_into().unwrap_or(u32::MAX),
                network_difficulty: self.consensus_converter.get_difficulty_ratio(consensus_stats.virtual_stats.bits),
                network_past_median_time: consensus_stats.virtual_stats.past_median_time,
                network_virtual_parent_hashes_count: consensus_stats.virtual_stats.num_parents,
                network_virtual_daa_score: consensus_stats.virtual_stats.daa_score,
            })
        } else {
            None
        };

        let storage_metrics = req.storage_metrics.then_some(StorageMetrics { storage_size_bytes: 0 });

        let minimum_relay_feerate =
            if req.custom_metrics { Some(self.mining_manager.clone().minimum_relay_feerate().await.max(0.0)) } else { None };

        let custom_metrics: Option<HashMap<String, CustomMetricValue>> = req.custom_metrics.then(|| {
            let hfa = self.hfa_engine.metrics_snapshot();
            let minimum_relay_feerate = minimum_relay_feerate.unwrap_or(0.0);
            let configured_hfa_feerate_floor = self.hfa_engine.config().min_feerate_floor.max(0.0);
            let effective_hfa_feerate_floor = self.hfa_engine.effective_feerate_floor(minimum_relay_feerate);
            let mut out = HashMap::new();
            out.insert("hfa_enabled".to_string(), CustomMetricValue::Bool(hfa.enabled));
            out.insert("hfa_node_epoch".to_string(), CustomMetricValue::U64(hfa.node_epoch));
            out.insert("hfa_mode".to_string(), CustomMetricValue::Text(hfa.mode.to_string()));
            let fast_recent_route_ids =
                self.hfa_engine.recent_fast_tx_route_ids(128).into_iter().map(|tx_id| tx_id.to_string()).collect::<Vec<_>>();
            out.insert("fast_recent_tx_ids".to_string(), CustomMetricValue::Text(fast_recent_route_ids.join(",")));
            out.insert("hfa_minimum_relay_feerate".to_string(), CustomMetricValue::F64(minimum_relay_feerate));
            out.insert("hfa_min_feerate_floor_config".to_string(), CustomMetricValue::F64(configured_hfa_feerate_floor));
            out.insert("hfa_effective_feerate_floor".to_string(), CustomMetricValue::F64(effective_hfa_feerate_floor));
            out.insert("fast_minimum_relay_feerate".to_string(), CustomMetricValue::F64(minimum_relay_feerate));
            out.insert("fast_effective_feerate_floor".to_string(), CustomMetricValue::F64(effective_hfa_feerate_floor));
            out.insert("hfa_paused_for_ms".to_string(), CustomMetricValue::U64(hfa.paused_for_ms));
            out.insert("fast_active_locks".to_string(), CustomMetricValue::U64(hfa.active_locks as u64));
            out.insert("fast_pending_intents".to_string(), CustomMetricValue::U64(hfa.pending_intents as u64));
            out.insert("fast_prelock_intents".to_string(), CustomMetricValue::U64(hfa.prelock_intents as u64));
            out.insert("fast_active_intents".to_string(), CustomMetricValue::U64(hfa.active_intents as u64));
            out.insert("fast_submit_total".to_string(), CustomMetricValue::U64(hfa.submit_total));
            out.insert("fast_submit_total_rpc".to_string(), CustomMetricValue::U64(hfa.submit_rpc_total));
            out.insert("fast_submit_total_p2p".to_string(), CustomMetricValue::U64(hfa.submit_p2p_total));
            out.insert("fast_reject_total".to_string(), CustomMetricValue::U64(hfa.rejected_total));
            out.insert("fast_overload_reject_total".to_string(), CustomMetricValue::U64(hfa.overload_reject_total));
            out.insert("fast_normal_conflict_reject_total".to_string(), CustomMetricValue::U64(hfa.normal_conflict_reject_total));
            out.insert("fast_drop_total".to_string(), CustomMetricValue::U64(hfa.dropped_total));
            out.insert("fast_expired_total".to_string(), CustomMetricValue::U64(hfa.expired_total));
            out.insert("fast_terminal_entries".to_string(), CustomMetricValue::U64(hfa.terminal_entries as u64));
            out.insert("fast_terminal_bytes".to_string(), CustomMetricValue::U64(hfa.terminal_bytes as u64));
            out.insert(
                "fast_terminal_evictions_total_retention".to_string(),
                CustomMetricValue::U64(hfa.terminal_evictions_retention_total),
            );
            out.insert(
                "fast_terminal_evictions_total_expired".to_string(),
                CustomMetricValue::U64(hfa.terminal_evictions_expired_total),
            );
            out.insert(
                "fast_terminal_evictions_total_oldest".to_string(),
                CustomMetricValue::U64(hfa.terminal_evictions_oldest_total),
            );
            out.insert("fast_arbiter_queue_len".to_string(), CustomMetricValue::U64(hfa.fast_arbiter_queue_len as u64));
            out.insert("fast_arbiter_queue_ratio".to_string(), CustomMetricValue::F64(hfa.fast_arbiter_queue_ratio));
            out.insert("fast_arbiter_wait_ms".to_string(), CustomMetricValue::F64(hfa.fast_arbiter_wait_ms));
            out.insert("fast_arbiter_hold_ms".to_string(), CustomMetricValue::F64(hfa.fast_arbiter_hold_ms));
            out.insert("fast_validation_queue_ratio".to_string(), CustomMetricValue::F64(hfa.fast_validation_queue_ratio));
            out.insert("fast_worker_cpu_ratio".to_string(), CustomMetricValue::F64(hfa.fast_worker_cpu_ratio));
            out.insert("basechain_block_latency_ms".to_string(), CustomMetricValue::F64(hfa.basechain_block_latency_ms));
            out.insert(
                "basechain_latency_delta_vs_baseline_ms".to_string(),
                CustomMetricValue::F64(hfa.basechain_latency_delta_vs_baseline_ms),
            );
            out.insert("fast_pull_miss_total".to_string(), CustomMetricValue::U64(hfa.pull_miss_total));
            out.insert("fast_pull_fail_total".to_string(), CustomMetricValue::U64(hfa.pull_fail_total));
            out.insert("fast_mode_transition_total".to_string(), CustomMetricValue::U64(hfa.mode_transition_total));
            out.insert(
                "fast_mode_transition_normal_to_degraded_total".to_string(),
                CustomMetricValue::U64(hfa.mode_transition_normal_to_degraded_total),
            );
            out.insert(
                "fast_mode_transition_degraded_to_paused_total".to_string(),
                CustomMetricValue::U64(hfa.mode_transition_degraded_to_paused_total),
            );
            out.insert(
                "fast_mode_transition_paused_to_degraded_total".to_string(),
                CustomMetricValue::U64(hfa.mode_transition_paused_to_degraded_total),
            );
            out.insert(
                "fast_mode_transition_degraded_to_normal_total".to_string(),
                CustomMetricValue::U64(hfa.mode_transition_degraded_to_normal_total),
            );
            out.insert("fast_revalidation_backlog_seconds".to_string(), CustomMetricValue::F64(hfa.revalidation_backlog_seconds));
            out
        });

        let server_time = unix_now();

        let response = GetMetricsResponse {
            server_time,
            process_metrics,
            connection_metrics,
            bandwidth_metrics,
            consensus_metrics,
            storage_metrics,
            custom_metrics,
        };

        Ok(response)
    }

    async fn get_system_info_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetSystemInfoRequest,
    ) -> RpcResult<GetSystemInfoResponse> {
        let response = GetSystemInfoResponse {
            version: self.system_info.version.clone(),
            system_id: self.system_info.system_id.clone(),
            git_hash: self.system_info.git_short_hash.clone(),
            cpu_physical_cores: self.system_info.cpu_physical_cores,
            total_memory: self.system_info.total_memory,
            fd_limit: self.system_info.fd_limit,
            proxy_socket_limit_per_cpu_core: self.system_info.proxy_socket_limit_per_cpu_core,
        };

        Ok(response)
    }

    async fn get_server_info_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetServerInfoRequest,
    ) -> RpcResult<GetServerInfoResponse> {
        let session = self.consensus_manager.consensus().unguarded_session();
        let is_synced: bool = self.has_sufficient_peer_connectivity() && session.async_is_nearly_synced().await;
        let virtual_daa_score = session.get_virtual_daa_score();

        Ok(GetServerInfoResponse {
            rpc_api_version: RPC_API_VERSION,
            rpc_api_revision: RPC_API_REVISION,
            server_version: version().to_string(),
            network_id: self.config.net,
            has_utxo_index: self.config.utxoindex,
            is_synced,
            virtual_daa_score,
        })
    }

    async fn get_sync_status_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetSyncStatusRequest,
    ) -> RpcResult<GetSyncStatusResponse> {
        let session = self.consensus_manager.consensus().unguarded_session();
        let is_synced: bool = self.has_sufficient_peer_connectivity() && session.async_is_nearly_synced().await;
        Ok(GetSyncStatusResponse { is_synced })
    }

    async fn get_strong_nodes_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetStrongNodesRequest,
    ) -> RpcResult<GetStrongNodesResponse> {
        let snapshot = self.flow_context.strong_node_claims_snapshot();
        let entries = snapshot
            .entries
            .into_iter()
            .map(|entry| RpcStrongNodeEntry {
                node_id: entry.node_id,
                public_key_xonly: entry.public_key_xonly,
                source: "claimant-v1".to_string(),
                claimed_blocks: entry.claimed_blocks,
                share_bps: entry.share_bps,
                last_claim_block_hash: entry.last_claim_block_hash,
                last_claim_time_ms: entry.last_claim_time_ms,
            })
            .collect();

        Ok(GetStrongNodesResponse {
            enabled_by_config: snapshot.enabled,
            hardfork_active: snapshot.hardfork_active,
            runtime_available: snapshot.runtime_available,
            disabled_reason_code: None,
            disabled_reason_message: None,
            conflict_total: snapshot.conflict_total,
            window_size: snapshot.window_size,
            entries,
        })
    }

    async fn simulate_token_op_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        request: SimulateTokenOpRequest,
    ) -> RpcResult<SimulateTokenOpResponse> {
        let SimulateTokenOpRequest { payload_hex, owner_id, at_block_hash } = request;
        let atomic = self.atomic_service()?;
        let view = atomic.get_read_view(at_block_hash).await.ok_or(RpcError::StaleContext)?;
        Self::ensure_token_simulation_ready(&view)?;
        let owner_id = Self::parse_hex_32(&owner_id, "ownerId")?;
        let payload = Vec::<u8>::from_hex(&payload_hex).map_err(|err| RpcError::General(format!("invalid `payloadHex`: {err}")))?;
        let expected_next_nonce = view.nonces.get(&owner_id).copied().unwrap_or(1);

        let (result, noop_reason) = match parse_atomic_token_payload(&payload) {
            None => ("ignored".to_string(), None),
            Some(Err(noop_reason)) => ("noop".to_string(), Some(noop_reason as u32)),
            Some(Ok(parsed)) => {
                let noop_reason = self.simulate_token_noop_reason(&view, owner_id, &parsed).map(|reason| reason as u32);
                if noop_reason.is_some() {
                    ("noop".to_string(), noop_reason)
                } else {
                    ("state_only".to_string(), None)
                }
            }
        };

        let context = self.atomic_context(&view).await?;
        Ok(SimulateTokenOpResponse { result, noop_reason, expected_next_nonce, context })
    }

    async fn get_token_balance_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        request: GetTokenBalanceRequest,
    ) -> RpcResult<GetTokenBalanceResponse> {
        let GetTokenBalanceRequest { asset_id, owner_id, at_block_hash } = request;
        let atomic = self.atomic_service()?;
        let asset_id = Self::parse_hex_32(&asset_id, "assetId")?;
        let owner_id = Self::parse_hex_32(&owner_id, "ownerId")?;
        let view = atomic.get_read_view(at_block_hash).await.ok_or(RpcError::StaleContext)?;
        Self::ensure_token_read_ready(&view)?;
        let balance =
            view.balances.get(&cryptix_atomicindex::state::BalanceKey { asset_id, owner_id }).copied().unwrap_or(0).to_string();
        let context = self.atomic_context(&view).await?;
        Ok(GetTokenBalanceResponse { balance, context })
    }

    async fn get_token_nonce_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        request: GetTokenNonceRequest,
    ) -> RpcResult<GetTokenNonceResponse> {
        let GetTokenNonceRequest { owner_id, at_block_hash } = request;
        let atomic = self.atomic_service()?;
        let owner_id = Self::parse_hex_32(&owner_id, "ownerId")?;
        let view = atomic.get_read_view(at_block_hash).await.ok_or(RpcError::StaleContext)?;
        Self::ensure_token_read_ready(&view)?;
        let expected_next_nonce = view.nonces.get(&owner_id).copied().unwrap_or(1);
        let context = self.atomic_context(&view).await?;
        Ok(GetTokenNonceResponse { expected_next_nonce, context })
    }

    async fn get_token_asset_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        request: GetTokenAssetRequest,
    ) -> RpcResult<GetTokenAssetResponse> {
        let GetTokenAssetRequest { asset_id, at_block_hash } = request;
        let atomic = self.atomic_service()?;
        let asset_id = Self::parse_hex_32(&asset_id, "assetId")?;
        let view = atomic.get_read_view(at_block_hash).await.ok_or(RpcError::StaleContext)?;
        Self::ensure_token_read_ready(&view)?;
        let asset = view.assets.get(&asset_id).cloned().map(Self::map_token_asset);
        let context = self.atomic_context(&view).await?;
        Ok(GetTokenAssetResponse { asset, context })
    }

    async fn get_token_op_status_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        request: GetTokenOpStatusRequest,
    ) -> RpcResult<GetTokenOpStatusResponse> {
        let GetTokenOpStatusRequest { txid, at_block_hash } = request;
        let atomic = self.atomic_service()?;
        let view = atomic.get_read_view(at_block_hash).await.ok_or(RpcError::StaleContext)?;
        Self::ensure_token_read_ready(&view)?;
        let context = self.atomic_context(&view).await?;
        let status = view.processed_ops.get(&txid).cloned();
        Ok(match status {
            Some(status) => Self::map_processed_op(status, context),
            None => GetTokenOpStatusResponse { accepting_block_hash: None, apply_status: None, noop_reason: None, context },
        })
    }

    async fn get_token_state_hash_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        request: GetTokenStateHashRequest,
    ) -> RpcResult<GetTokenStateHashResponse> {
        let GetTokenStateHashRequest { at_block_hash } = request;
        let atomic = self.atomic_service()?;
        let view = atomic.get_read_view(at_block_hash).await.ok_or(RpcError::StaleContext)?;
        Self::ensure_token_read_ready(&view)?;
        let context = self.atomic_context(&view).await?;
        Ok(GetTokenStateHashResponse { context })
    }

    async fn get_token_spendability_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        request: GetTokenSpendabilityRequest,
    ) -> RpcResult<GetTokenSpendabilityResponse> {
        let GetTokenSpendabilityRequest { asset_id, owner_id, min_daa_for_spend, at_block_hash } = request;
        let atomic = self.atomic_service()?;
        let asset_id = Self::parse_hex_32(&asset_id, "assetId")?;
        let owner_id = Self::parse_hex_32(&owner_id, "ownerId")?;
        let min_daa_for_spend = min_daa_for_spend.unwrap_or(10);
        let view = atomic.get_read_view(at_block_hash).await.ok_or(RpcError::StaleContext)?;
        match view.runtime_state {
            AtomicTokenRuntimeState::NotReady => return Err(RpcError::AtomicStateNotReady),
            AtomicTokenRuntimeState::Recovering => return Err(RpcError::AtomicStateRecovering),
            AtomicTokenRuntimeState::Healthy | AtomicTokenRuntimeState::Degraded => {}
        }
        let balance = view.balances.get(&cryptix_atomicindex::state::BalanceKey { asset_id, owner_id }).copied().unwrap_or(0);
        let anchor_count = view.anchor_counts.get(&owner_id).copied().unwrap_or(0);
        let expected_next_nonce = view.nonces.get(&owner_id).copied().unwrap_or(1);
        let context = self.atomic_context(&view).await?;

        let (can_spend, reason) = if context.is_degraded {
            (false, Some("token_state_degraded".to_string()))
        } else if context.at_daa_score < min_daa_for_spend {
            (false, Some("min_daa_not_reached".to_string()))
        } else if balance == 0 {
            (false, Some("zero_balance".to_string()))
        } else if anchor_count == 0 {
            (false, Some("missing_anchor_utxo".to_string()))
        } else {
            (true, None)
        };

        Ok(GetTokenSpendabilityResponse {
            can_spend,
            reason,
            balance: balance.to_string(),
            expected_next_nonce,
            min_daa_for_spend,
            context,
        })
    }

    async fn get_token_events_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        request: GetTokenEventsRequest,
    ) -> RpcResult<GetTokenEventsResponse> {
        let GetTokenEventsRequest { after_sequence, limit, at_block_hash } = request;
        let atomic = self.atomic_service()?;
        let limit = usize::try_from(limit).map_err(|e| RpcError::General(e.to_string()))?.min(TOKEN_EVENTS_LIMIT_MAX);
        let view = atomic.get_read_view(at_block_hash).await.ok_or(RpcError::StaleContext)?;
        Self::ensure_token_read_ready(&view)?;
        let events = atomic
            .get_events_since_capped(after_sequence, limit, view.event_sequence_cutoff)
            .await
            .into_iter()
            .map(Self::map_token_event)
            .collect();
        let context = self.atomic_context(&view).await?;
        Ok(GetTokenEventsResponse { events, context })
    }

    async fn get_token_assets_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        request: GetTokenAssetsRequest,
    ) -> RpcResult<GetTokenAssetsResponse> {
        let GetTokenAssetsRequest { offset, limit, query, at_block_hash } = request;
        let atomic = self.atomic_service()?;
        let limit = usize::try_from(limit).map_err(|e| RpcError::General(e.to_string()))?.min(TOKEN_ASSETS_LIMIT_MAX);
        let offset = usize::try_from(offset).map_err(|e| RpcError::General(e.to_string()))?;
        let view = atomic.get_read_view(at_block_hash).await.ok_or(RpcError::StaleContext)?;
        Self::ensure_token_read_ready(&view)?;
        let query = query.unwrap_or_default();

        let mut assets: Vec<TokenAsset> =
            view.assets.values().filter(|asset| Self::token_asset_matches_query(asset, &query)).cloned().collect();
        assets.sort_by(|a, b| {
            let a_symbol = String::from_utf8_lossy(&a.symbol);
            let b_symbol = String::from_utf8_lossy(&b.symbol);
            a_symbol
                .cmp(&b_symbol)
                .then_with(|| String::from_utf8_lossy(&a.name).cmp(&String::from_utf8_lossy(&b.name)))
                .then_with(|| a.asset_id.cmp(&b.asset_id))
        });

        let total = assets.len() as u64;
        let assets = assets.into_iter().skip(offset).take(limit).map(Self::map_token_asset).collect();
        let context = self.atomic_context(&view).await?;
        Ok(GetTokenAssetsResponse { assets, total, context })
    }

    async fn get_token_balances_by_owner_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        request: GetTokenBalancesByOwnerRequest,
    ) -> RpcResult<GetTokenBalancesByOwnerResponse> {
        let GetTokenBalancesByOwnerRequest { owner_id, offset, limit, include_assets, at_block_hash } = request;
        let atomic = self.atomic_service()?;
        let owner_id = Self::parse_hex_32(&owner_id, "ownerId")?;
        let limit = usize::try_from(limit).map_err(|e| RpcError::General(e.to_string()))?.min(TOKEN_OWNER_BALANCES_LIMIT_MAX);
        let offset = usize::try_from(offset).map_err(|e| RpcError::General(e.to_string()))?;
        let view = atomic.get_read_view(at_block_hash).await.ok_or(RpcError::StaleContext)?;
        Self::ensure_token_read_ready(&view)?;

        let mut balances: Vec<([u8; 32], u128, Option<TokenAsset>)> = view
            .balances
            .iter()
            .filter_map(|(key, balance)| {
                if key.owner_id != owner_id || *balance == 0 {
                    return None;
                }
                let asset = if include_assets { view.assets.get(&key.asset_id).cloned() } else { None };
                Some((key.asset_id, *balance, asset))
            })
            .collect();

        balances.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let total = balances.len() as u64;
        let balances = balances.into_iter().skip(offset).take(limit).map(Self::map_token_owner_balance).collect();
        let context = self.atomic_context(&view).await?;
        Ok(GetTokenBalancesByOwnerResponse { balances, total, context })
    }

    async fn get_token_holders_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        request: GetTokenHoldersRequest,
    ) -> RpcResult<GetTokenHoldersResponse> {
        let GetTokenHoldersRequest { asset_id, offset, limit, at_block_hash } = request;
        let atomic = self.atomic_service()?;
        let asset_id = Self::parse_hex_32(&asset_id, "assetId")?;
        let limit = usize::try_from(limit).map_err(|e| RpcError::General(e.to_string()))?.min(TOKEN_HOLDERS_LIMIT_MAX);
        let offset = usize::try_from(offset).map_err(|e| RpcError::General(e.to_string()))?;
        let view = atomic.get_read_view(at_block_hash).await.ok_or(RpcError::StaleContext)?;
        Self::ensure_token_read_ready(&view)?;

        let mut holders: Vec<([u8; 32], u128)> = view
            .balances
            .iter()
            .filter_map(|(key, balance)| if key.asset_id == asset_id && *balance > 0 { Some((key.owner_id, *balance)) } else { None })
            .collect();
        holders.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

        let total = holders.len() as u64;
        let holders = holders.into_iter().skip(offset).take(limit).map(Self::map_token_holder).collect();
        let context = self.atomic_context(&view).await?;
        Ok(GetTokenHoldersResponse { holders, total, context })
    }

    async fn get_token_owner_id_by_address_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        request: GetTokenOwnerIdByAddressRequest,
    ) -> RpcResult<GetTokenOwnerIdByAddressResponse> {
        let GetTokenOwnerIdByAddressRequest { address, at_block_hash } = request;
        let atomic = self.atomic_service()?;
        let view = atomic.get_read_view(at_block_hash).await.ok_or(RpcError::StaleContext)?;
        Self::ensure_token_read_ready(&view)?;
        let address = Address::try_from(address.as_str()).map_err(|e| RpcError::General(format!("invalid `address` string: {e}")))?;
        let script_public_key = pay_to_address_script(&address);
        let (owner_id, reason) = match Self::owner_id_from_script(&script_public_key) {
            Some(owner_id) => (Some(owner_id.as_slice().to_hex()), None),
            None => (None, Some("unsupported_script_class".to_string())),
        };
        let context = self.atomic_context(&view).await?;
        Ok(GetTokenOwnerIdByAddressResponse { owner_id, reason, context })
    }

    async fn export_token_snapshot_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        request: ExportTokenSnapshotRequest,
    ) -> RpcResult<ExportTokenSnapshotResponse> {
        let atomic = self.atomic_service()?;
        if !self.config.unsafe_rpc {
            warn!("ExportTokenSnapshot RPC command called while node in safe RPC mode -- rejecting.");
            return Err(RpcError::UnavailableInSafeMode);
        }
        atomic.export_snapshot_to_file(&request.path).await.map_err(|err| RpcError::General(err.to_string()))?;
        let view = atomic.get_read_view(None).await.ok_or(RpcError::StaleContext)?;
        let context = self.atomic_context(&view).await?;
        Ok(ExportTokenSnapshotResponse { exported: true, context })
    }

    async fn import_token_snapshot_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        request: ImportTokenSnapshotRequest,
    ) -> RpcResult<ImportTokenSnapshotResponse> {
        let atomic = self.atomic_service()?;
        if !self.config.unsafe_rpc {
            warn!("ImportTokenSnapshot RPC command called while node in safe RPC mode -- rejecting.");
            return Err(RpcError::UnavailableInSafeMode);
        }
        atomic.import_snapshot_from_file(&request.path).await.map_err(|err| RpcError::General(err.to_string()))?;
        let view = atomic.get_read_view(None).await.ok_or(RpcError::StaleContext)?;
        let context = self.atomic_context(&view).await?;
        Ok(ImportTokenSnapshotResponse { imported: true, context })
    }

    async fn get_token_health_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        request: GetTokenHealthRequest,
    ) -> RpcResult<GetTokenHealthResponse> {
        let GetTokenHealthRequest { at_block_hash } = request;
        let atomic = self.atomic_service()?;
        let view = atomic.get_read_view(at_block_hash).await.ok_or(RpcError::StaleContext)?;
        let health = atomic.get_health().await;
        let context = self.atomic_context(&view).await?;
        Ok(Self::map_health_response(health, context))
    }

    async fn get_sc_bootstrap_sources_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetScBootstrapSourcesRequest,
    ) -> RpcResult<GetScBootstrapSourcesResponse> {
        let atomic = self.atomic_service()?;
        let view = atomic.get_read_view(None).await.ok_or(RpcError::StaleContext)?;
        let context = self.atomic_context(&view).await?;
        let sources = atomic
            .get_sc_bootstrap_sources()
            .await
            .map_err(|err| RpcError::General(err.to_string()))?
            .into_iter()
            .map(Self::map_sc_bootstrap_source)
            .collect();
        Ok(GetScBootstrapSourcesResponse { sources, context })
    }

    async fn get_sc_snapshot_manifest_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        request: GetScSnapshotManifestRequest,
    ) -> RpcResult<GetScSnapshotManifestResponse> {
        let atomic = self.atomic_service()?;
        let manifest_payload =
            atomic.get_sc_snapshot_manifest(&request.snapshot_id).await.map_err(|err| RpcError::General(err.to_string()))?;
        Ok(GetScSnapshotManifestResponse {
            snapshot_id: manifest_payload.snapshot_id,
            manifest_hex: manifest_payload.manifest_bytes.to_hex(),
            manifest_signatures: manifest_payload.signatures.into_iter().map(Self::map_sc_manifest_signature).collect(),
        })
    }

    async fn get_sc_snapshot_chunk_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        request: GetScSnapshotChunkRequest,
    ) -> RpcResult<GetScSnapshotChunkResponse> {
        let atomic = self.atomic_service()?;
        let chunk = atomic
            .get_sc_snapshot_chunk(&request.snapshot_id, request.chunk_index, request.chunk_size)
            .await
            .map_err(|err| RpcError::General(err.to_string()))?;
        Ok(Self::map_sc_chunk(chunk))
    }

    async fn get_sc_replay_window_chunk_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        request: GetScReplayWindowChunkRequest,
    ) -> RpcResult<GetScReplayWindowChunkResponse> {
        let atomic = self.atomic_service()?;
        let chunk = atomic
            .get_sc_replay_window_chunk(&request.snapshot_id, request.chunk_index, request.chunk_size)
            .await
            .map_err(|err| RpcError::General(err.to_string()))?;
        Ok(GetScReplayWindowChunkResponse {
            snapshot_id: chunk.snapshot_id,
            chunk_index: chunk.chunk_index,
            total_chunks: chunk.total_chunks,
            file_size: chunk.file_size,
            chunk_hex: chunk.chunk_data.to_hex(),
        })
    }

    async fn get_sc_snapshot_head_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetScSnapshotHeadRequest,
    ) -> RpcResult<GetScSnapshotHeadResponse> {
        let atomic = self.atomic_service()?;
        let view = atomic.get_read_view(None).await.ok_or(RpcError::StaleContext)?;
        let context = self.atomic_context(&view).await?;
        let head =
            atomic.get_sc_snapshot_head().await.map_err(|err| RpcError::General(err.to_string()))?.map(Self::map_sc_bootstrap_source);
        Ok(GetScSnapshotHeadResponse { head, context })
    }

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Notification API

    /// Register a new listener and returns an id identifying it.
    fn register_new_listener(&self, connection: ChannelConnection) -> ListenerId {
        self.notifier.register_new_listener(connection, ListenerLifespan::Dynamic)
    }

    /// Unregister an existing listener.
    ///
    /// Stop all notifications for this listener, unregister the id and its associated connection.
    async fn unregister_listener(&self, id: ListenerId) -> RpcResult<()> {
        self.notifier.unregister_listener(id)?;
        Ok(())
    }

    /// Start sending notifications of some type to a listener.
    async fn start_notify(&self, id: ListenerId, scope: Scope) -> RpcResult<()> {
        match scope {
            Scope::UtxosChanged(ref utxos_changed_scope) if !self.config.unsafe_rpc && utxos_changed_scope.addresses.is_empty() => {
                // The subscription to blanket UtxosChanged notifications is restricted to unsafe mode only
                // since the notifications yielded are highly resource intensive.
                //
                // Please note that unsubscribing to blanket UtxosChanged is always allowed and cancels
                // the whole subscription no matter if blanket or targeting specified addresses.

                warn!("RPC subscription to blanket UtxosChanged called while node in safe RPC mode -- ignoring.");
                Err(RpcError::UnavailableInSafeMode)
            }
            _ => {
                self.notifier.clone().start_notify(id, scope).await?;
                Ok(())
            }
        }
    }

    /// Stop sending notifications of some type to a listener.
    async fn stop_notify(&self, id: ListenerId, scope: Scope) -> RpcResult<()> {
        self.notifier.clone().stop_notify(id, scope).await?;
        Ok(())
    }
}

// It might be necessary to opt this out in the context of wasm32

impl AsyncService for RpcCoreService {
    fn ident(self: Arc<Self>) -> &'static str {
        Self::IDENT
    }

    fn start(self: Arc<Self>) -> AsyncServiceFuture {
        trace!("{} starting", Self::IDENT);
        let service = self.clone();

        // Prepare a shutdown signal receiver
        let shutdown_signal = self.shutdown.listener.clone();

        // Launch the service and wait for a shutdown signal
        Box::pin(async move {
            service.clone().start_impl();
            shutdown_signal.await;
            match service.join().await {
                Ok(_) => Ok(()),
                Err(err) => {
                    warn!("Error while stopping {}: {}", Self::IDENT, err);
                    Err(AsyncServiceError::Service(err.to_string()))
                }
            }
        })
    }

    fn signal_exit(self: Arc<Self>) {
        trace!("sending an exit signal to {}", Self::IDENT);
        self.shutdown.trigger.trigger();
    }

    fn stop(self: Arc<Self>) -> AsyncServiceFuture {
        Box::pin(async move {
            trace!("{} stopped", Self::IDENT);
            Ok(())
        })
    }
}
