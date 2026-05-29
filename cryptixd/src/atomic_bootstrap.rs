use async_trait::async_trait;
use blake2b_simd::Params as Blake2bParams;
use borsh::BorshDeserialize;
use cryptix_atomicindex::{
    service::{AtomicTokenService, MAX_BOOTSTRAP_REPLAY_WINDOW_SIZE_BYTES, MAX_BOOTSTRAP_SNAPSHOT_FILE_SIZE_BYTES},
    state::{AtomicTokenHealth, AtomicTokenRuntimeState},
};
use cryptix_consensus_core::Hash as BlockHash;
use cryptix_core::{
    info,
    task::service::{AsyncService, AsyncServiceFuture},
    trace, warn,
};
use cryptix_grpc_client::GrpcClient;
use cryptix_p2p_flows::flow_context::{AtomicStateQuorumVerifier, FlowContext};
use cryptix_p2p_lib::{
    make_request,
    pb::{cryptixd_message::Payload, RequestAtomicTokenStateHashMessage, RequestConsensusAtomicStateHashMessage},
    Router,
};
use cryptix_rpc_core::{
    api::rpc::RpcApi,
    model::message::{
        GetConsensusAtomicStateHashRequest, GetScReplayWindowChunkRequest, GetScSnapshotChunkRequest, RpcScBootstrapSource,
    },
};
use cryptix_utils::triggers::SingleTrigger;
use futures_util::future::join_all;
use hex::{decode as hex_decode, encode as hex_encode};
use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    hash::{Hash, Hasher},
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::Mutex,
    time::{interval, timeout, MissedTickBehavior},
};

const SERVICE_IDENT: &str = "atomic-bootstrap-service";
const SNAPSHOT_MANIFEST_DOMAIN: &[u8] = b"CRYPTIX_ATOMIC_SNAPSHOT_MANIFEST_V2";
const SNAPSHOT_ID_DOMAIN: &[u8] = b"CAT_SNAPSHOT_ID_V2";
const MAX_REMOTE_SOURCES: usize = 64;
const P2P_AUDIT_MIN_SAMPLE_SOURCES: usize = 4;
const P2P_AUDIT_MAX_SAMPLE_SOURCES: usize = 12;
const RPC_CALL_TIMEOUT: Duration = Duration::from_secs(15);
const P2P_ATOMIC_STATE_HASH_TIMEOUT: Duration = Duration::from_secs(15);
const SOURCE_FAILURE_THRESHOLD: u32 = 3;
const SOURCE_RETRY_COOLDOWN: Duration = Duration::from_secs(300);
pub(crate) const ATOMIC_BOOTSTRAP_REQUIRED_SEED_SOURCES: usize = 1;
pub(crate) const ATOMIC_BOOTSTRAP_DEFAULT_SEED_CONFIRMED_NON_SEED_SOURCES: usize = 2;
pub(crate) const ATOMIC_BOOTSTRAP_REQUIRED_TOTAL_SOURCES: usize =
    ATOMIC_BOOTSTRAP_REQUIRED_SEED_SOURCES + ATOMIC_BOOTSTRAP_DEFAULT_SEED_CONFIRMED_NON_SEED_SOURCES;
pub(crate) const ATOMIC_BOOTSTRAP_DEFAULT_PEER_MAJORITY_MIN_SOURCES: usize = ATOMIC_BOOTSTRAP_REQUIRED_TOTAL_SOURCES;
const MAX_MANIFEST_HEX_LEN: usize = 4 * 1024 * 1024;
const MAX_ALLOWED_CHUNK_SIZE: u32 = 4 * 1024 * 1024;
const MAX_SNAPSHOT_FILE_SIZE_BYTES: u64 = MAX_BOOTSTRAP_SNAPSHOT_FILE_SIZE_BYTES;
const MAX_REPLAY_FILE_SIZE_BYTES: u64 = MAX_BOOTSTRAP_REPLAY_WINDOW_SIZE_BYTES;
const MAX_TOTAL_CHUNKS: usize = 65_536;
const PENDING_AUDIT_LOG_INTERVAL: Duration = Duration::from_secs(300);
#[allow(dead_code)]
#[derive(Clone, Debug, BorshDeserialize)]
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

#[derive(Clone)]
struct SourceClient {
    endpoint: String,
    source_identity: String,
    kind: SourceKind,
    client: GrpcClient,
    head: RpcScBootstrapSource,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SourceKind {
    Configured,
    Seed,
    Peer,
}

#[derive(Clone, Debug)]
struct CandidateEndpoint {
    endpoint: String,
    expected_node_identity: Option<[u8; 32]>,
    kind: SourceKind,
}

#[derive(Clone, Debug, Default)]
struct SourcePenalty {
    failures: u32,
    blocked_until: Option<Instant>,
}

#[derive(Clone, Debug)]
struct SnapshotSupportEvidence {
    source_identity: String,
    source_label: String,
    snapshot_id: String,
    kind: SourceKind,
    at_daa_score: u64,
    at_block_hash: String,
}

#[derive(Clone, Debug)]
struct SnapshotQuorumDecision {
    snapshot_id: String,
    required_votes: usize,
    policy_description: String,
}

struct P2pAuditPeerCandidate {
    router: Arc<Router>,
    source_identity: String,
}

#[derive(Clone, Copy, Debug)]
struct SnapshotQuorumPolicy {
    allow_peer_majority_fallback: bool,
    require_seed_confirmed_if_any_seed: bool,
    seed_confirmed_min_non_seed_sources: usize,
    peer_majority_min_sources: usize,
}

struct BootstrapSelection {
    snapshot_id: String,
    sources: Vec<SourceClient>,
    required_votes: usize,
    policy_description: String,
}

pub struct AtomicBootstrapService {
    atomic_token_service: Arc<AtomicTokenService>,
    flow_context: Arc<FlowContext>,
    configured_rpc_peers: Vec<cryptix_addressmanager::NetAddress>,
    disable_dns_seed_sources: bool,
    atomic_data_dir: PathBuf,
    retry_interval: Duration,
    health_audit_enabled: bool,
    health_audit_interval: Duration,
    last_health_audit: Mutex<Option<Instant>>,
    last_pending_audit_logs: Mutex<HashMap<&'static str, Instant>>,
    bootstrap_attempt_lock: Mutex<()>,
    audit_context_revalidation_attempted: AtomicBool,
    source_penalties: Mutex<HashMap<String, SourcePenalty>>,
    allow_peer_majority_fallback_override: bool,
    seed_confirmed_min_non_seed_sources: usize,
    peer_majority_min_sources: usize,
    shutdown: SingleTrigger,
}

impl AtomicBootstrapService {
    pub fn new(
        atomic_token_service: Arc<AtomicTokenService>,
        flow_context: Arc<FlowContext>,
        configured_rpc_peers: Vec<cryptix_addressmanager::NetAddress>,
        disable_dns_seed_sources: bool,
        retry_interval_sec: u64,
        atomic_data_dir: PathBuf,
        allow_peer_majority_fallback_override: bool,
        peer_majority_min_sources_override: Option<usize>,
        health_audit_enabled: bool,
        health_audit_interval_minutes: u64,
    ) -> Result<Self, String> {
        let retry_interval_sec = retry_interval_sec.max(5);
        let health_audit_interval = Duration::from_secs(health_audit_interval_minutes.max(1).saturating_mul(60));
        let initial_health_audit_delay = health_audit_initial_delay(health_audit_interval, &atomic_data_dir);
        let initial_last_health_audit = Instant::now()
            .checked_sub(health_audit_interval.checked_sub(initial_health_audit_delay).unwrap_or_default())
            .unwrap_or_else(Instant::now);
        let peer_majority_min_sources =
            peer_majority_min_sources_override.unwrap_or(ATOMIC_BOOTSTRAP_DEFAULT_PEER_MAJORITY_MIN_SOURCES);
        let seed_confirmed_min_non_seed_sources =
            peer_majority_min_sources_override.unwrap_or(ATOMIC_BOOTSTRAP_DEFAULT_SEED_CONFIRMED_NON_SEED_SOURCES);
        if peer_majority_min_sources == 0 {
            return Err("Atomic bootstrap peer-only quorum minimum must be greater than 0".to_string());
        }
        if seed_confirmed_min_non_seed_sources == 0 {
            return Err("Atomic seed-confirmed bootstrap quorum non-seed minimum must be greater than 0".to_string());
        }
        if flow_context.config.net.is_mainnet() {
            if disable_dns_seed_sources && allow_peer_majority_fallback_override {
                info!(
                    "[atomic-bootstrap] mainnet DNS seed bootstrap disabled by operator (--nodnsseed); peer-only fallback ENABLED by explicit override"
                );
            } else if disable_dns_seed_sources {
                info!("[atomic-bootstrap] mainnet DNS seed bootstrap disabled by operator (--nodnsseed); peer-only fallback DISABLED");
            } else if allow_peer_majority_fallback_override {
                info!("[atomic-bootstrap] mainnet peer-only fallback override ENABLED; used only when no seed source is reachable");
            } else {
                info!("[atomic-bootstrap] mainnet peer-only fallback override DISABLED");
            }
        }
        if let Some(override_value) = peer_majority_min_sources_override {
            info!(
                "[atomic-bootstrap] Atomic bootstrap independent non-seed quorum minimum overridden: {} source(s) (seed-confirmed default: {}, peer-only default: {})",
                override_value,
                ATOMIC_BOOTSTRAP_DEFAULT_SEED_CONFIRMED_NON_SEED_SOURCES,
                ATOMIC_BOOTSTRAP_DEFAULT_PEER_MAJORITY_MIN_SOURCES
            );
        }
        if health_audit_enabled {
            info!(
                "[atomic-bootstrap:p2p] periodic healthy-state audit enabled: interval={} minute(s), first-check-stagger={}s",
                health_audit_interval.as_secs() / 60,
                initial_health_audit_delay.as_secs()
            );
        } else {
            info!("[atomic-bootstrap:p2p] periodic healthy-state audit disabled by operator");
        }
        Ok(Self {
            atomic_token_service,
            flow_context,
            configured_rpc_peers,
            disable_dns_seed_sources,
            atomic_data_dir,
            retry_interval: Duration::from_secs(retry_interval_sec),
            health_audit_enabled,
            health_audit_interval,
            last_health_audit: Mutex::new(Some(initial_last_health_audit)),
            last_pending_audit_logs: Default::default(),
            bootstrap_attempt_lock: Default::default(),
            audit_context_revalidation_attempted: AtomicBool::new(false),
            source_penalties: Default::default(),
            allow_peer_majority_fallback_override,
            seed_confirmed_min_non_seed_sources,
            peer_majority_min_sources,
            shutdown: Default::default(),
        })
    }

    fn snapshot_quorum_policy(&self) -> SnapshotQuorumPolicy {
        snapshot_quorum_policy_for_network(
            self.flow_context.config.net.is_mainnet(),
            self.disable_dns_seed_sources,
            self.allow_peer_majority_fallback_override,
            self.seed_confirmed_min_non_seed_sources,
            self.peer_majority_min_sources,
        )
    }

    fn no_sources_reason(&self) -> String {
        if !self.configured_rpc_peers.is_empty() {
            return format!(
                "no compatible bootstrap sources found (P2P quorum/local replay unavailable and {} optional --atomic-bootstrap-peer RPC source(s) did not serve a compatible live-correct Atomic snapshot; check peer Atomic health and snapshot freshness)",
                self.configured_rpc_peers.len()
            );
        }
        if self.disable_dns_seed_sources && self.flow_context.config.net.is_mainnet() && !self.allow_peer_majority_fallback_override {
            "no optional --atomic-bootstrap-peer RPC snapshot source configured; mainnet peer-only Atomic fallback is disabled unless --atomic-bootstrap-allow-peer-fallback is explicitly set".to_string()
        } else if self.disable_dns_seed_sources {
            "no optional --atomic-bootstrap-peer RPC snapshot source configured; local replay and P2P pruning-point Atomic state sync remain authoritative".to_string()
        } else {
            "no optional --atomic-bootstrap-peer RPC snapshot source configured; DNS seeds are only used for P2P discovery, not hidden RPC snapshot downloads".to_string()
        }
    }

    fn log_candidate_unavailable(candidate: &CandidateEndpoint, reason: &str) {
        if matches!(candidate.kind, SourceKind::Configured) {
            info!("[atomic-bootstrap] configured --atomic-bootstrap-peer {} unavailable: {}", candidate.endpoint, reason);
        } else {
            trace!("[atomic-bootstrap] source {} unavailable: {}", candidate.endpoint, reason);
        }
    }

    async fn should_run_health_audit(&self) -> bool {
        if !self.health_audit_enabled {
            return false;
        }
        let now = Instant::now();
        let mut guard = self.last_health_audit.lock().await;
        if let Some(last) = *guard {
            if now.duration_since(last) < self.health_audit_interval {
                return false;
            }
        }
        *guard = Some(now);
        true
    }

    async fn log_pending_audit(&self, reason: &'static str, message: String) {
        let now = Instant::now();
        let mut guard = self.last_pending_audit_logs.lock().await;
        let should_log = guard.get(reason).map(|last| now.duration_since(*last) >= PENDING_AUDIT_LOG_INTERVAL).unwrap_or(true);
        if should_log {
            guard.insert(reason, now);
            info!("{message}");
        } else {
            trace!("{message}");
        }
    }

    async fn collect_compatible_sources(&self, protocol_version: u32, network_id: &str) -> Vec<SourceClient> {
        let mut sources: Vec<SourceClient> = Vec::new();
        let candidates = self.candidate_endpoints();
        if candidates.is_empty() {
            trace!("[atomic-bootstrap:rpc] optional RPC snapshot bootstrap disabled: no --atomic-bootstrap-peer configured");
            return sources;
        }
        trace!("[atomic-bootstrap:rpc] collecting Atomic snapshot sources from {} configured RPC endpoint(s)", candidates.len());

        for candidate in candidates.into_iter().take(MAX_REMOTE_SOURCES) {
            if self.is_source_blocked(&candidate.endpoint).await {
                Self::log_candidate_unavailable(&candidate, "on temporary retry cooldown after repeated bootstrap failures");
                continue;
            }

            let client = match timeout(RPC_CALL_TIMEOUT, GrpcClient::connect(candidate.endpoint.clone())).await {
                Ok(Ok(client)) => client,
                Ok(Err(err)) => {
                    self.record_source_failure(&candidate.endpoint).await;
                    Self::log_candidate_unavailable(
                        &candidate,
                        &format!("RPC connect failed: {err}; use the peer RPC/GRPC port, not the P2P listen port"),
                    );
                    continue;
                }
                Err(_) => {
                    self.record_source_failure(&candidate.endpoint).await;
                    Self::log_candidate_unavailable(
                        &candidate,
                        &format!("RPC connect timed out after {}s", RPC_CALL_TIMEOUT.as_secs()),
                    );
                    continue;
                }
            };

            let candidate_sources = match timeout(RPC_CALL_TIMEOUT, client.get_sc_bootstrap_sources()).await {
                Ok(Ok(response)) => response.sources,
                Ok(Err(err)) => {
                    trace!(
                        "[atomic-bootstrap] getScBootstrapSources failed on {}; falling back to getScSnapshotHead: {err}",
                        candidate.endpoint
                    );
                    match timeout(RPC_CALL_TIMEOUT, client.get_sc_snapshot_head()).await {
                        Ok(Ok(response)) => response.head.into_iter().collect(),
                        Ok(Err(err)) => {
                            self.record_source_failure(&candidate.endpoint).await;
                            Self::log_candidate_unavailable(&candidate, &format!("getScSnapshotHead RPC failed: {err}"));
                            let _ = client.disconnect().await;
                            continue;
                        }
                        Err(_) => {
                            self.record_source_failure(&candidate.endpoint).await;
                            Self::log_candidate_unavailable(
                                &candidate,
                                &format!("getScSnapshotHead timed out after {}s", RPC_CALL_TIMEOUT.as_secs()),
                            );
                            let _ = client.disconnect().await;
                            continue;
                        }
                    }
                }
                Err(_) => {
                    self.record_source_failure(&candidate.endpoint).await;
                    Self::log_candidate_unavailable(
                        &candidate,
                        &format!("getScBootstrapSources timed out after {}s", RPC_CALL_TIMEOUT.as_secs()),
                    );
                    let _ = client.disconnect().await;
                    continue;
                }
            };

            if candidate_sources.is_empty() {
                Self::log_candidate_unavailable(
                    &candidate,
                    "returned no Atomic bootstrap snapshots; remote Atomic may still be revalidating, degraded, or below the finality-safe snapshot depth",
                );
                let _ = client.disconnect().await;
                continue;
            }

            let mut accepted = 0usize;
            for head in candidate_sources {
                if head.protocol_version != protocol_version || head.network_id != network_id {
                    trace!(
                        "[atomic-bootstrap] skipping incompatible Atomic snapshot from {} (expected protocol {}, network {}; got protocol {}, network {})",
                        candidate.endpoint,
                        protocol_version,
                        network_id,
                        head.protocol_version,
                        head.network_id
                    );
                    continue;
                }

                let source_identity_bytes = match decode_hash32_hex(&head.node_identity) {
                    Ok(identity) => identity,
                    Err(err) => {
                        self.record_source_failure(&candidate.endpoint).await;
                        trace!(
                            "[atomic-bootstrap] skipping Atomic snapshot from {} with invalid/missing canonical node identity: {}",
                            candidate.endpoint,
                            err
                        );
                        continue;
                    }
                };
                if let Some(expected_node_identity) = candidate.expected_node_identity {
                    if expected_node_identity != source_identity_bytes {
                        self.record_source_failure(&candidate.endpoint).await;
                        trace!(
                            "[atomic-bootstrap] skipping Atomic snapshot from {} due to canonical node identity mismatch (expected {}, got {})",
                            candidate.endpoint,
                            hex_encode(expected_node_identity),
                            hex_encode(source_identity_bytes)
                        );
                        continue;
                    }
                }

                accepted = accepted.saturating_add(1);
                sources.push(SourceClient {
                    endpoint: candidate.endpoint.clone(),
                    source_identity: hex_encode(source_identity_bytes),
                    kind: candidate.kind,
                    client: client.clone(),
                    head,
                });
            }

            if accepted == 0 {
                Self::log_candidate_unavailable(
                    &candidate,
                    "served Atomic bootstrap snapshots, but none were compatible with the expected network/protocol/source identity",
                );
                let _ = client.disconnect().await;
                continue;
            }

            self.record_source_success(&candidate.endpoint).await;
        }

        sources
    }

    async fn verify_consensus_atomic_state_hash_quorum(
        &self,
        block_hash: BlockHash,
        expected_state_hash: [u8; 32],
    ) -> Result<(), String> {
        self.verify_consensus_atomic_state_hash_quorum_with_anchor(block_hash, expected_state_hash, None).await
    }

    async fn verify_consensus_atomic_state_hash_quorum_at_daa(
        &self,
        block_hash: BlockHash,
        expected_state_hash: [u8; 32],
        anchor_daa_score: u64,
    ) -> Result<(), String> {
        self.verify_consensus_atomic_state_hash_quorum_with_anchor(block_hash, expected_state_hash, Some(anchor_daa_score)).await
    }

    async fn verify_consensus_atomic_state_hash_quorum_with_anchor(
        &self,
        block_hash: BlockHash,
        expected_state_hash: [u8; 32],
        anchor_daa_score: Option<u64>,
    ) -> Result<(), String> {
        let p2p_result = self.verify_consensus_atomic_state_hash_p2p_quorum(block_hash, expected_state_hash, anchor_daa_score).await;
        match p2p_result {
            Ok(()) => return Ok(()),
            Err(err) if self.configured_rpc_peers.is_empty() => return Err(err),
            Err(err) => trace!("[atomic-bootstrap] P2P Atomic state hash quorum unavailable; trying optional RPC sources: {err}"),
        }

        let protocol_version = self.atomic_token_service.protocol_version() as u32;
        let network_id = self.atomic_token_service.network_id().to_string();
        let expected_state_hash_hex = hex_encode(expected_state_hash);
        let sources = self.collect_compatible_sources(protocol_version, &network_id).await;
        if sources.is_empty() {
            return Err(self.no_sources_reason());
        }

        let mut evidence = Vec::new();
        for source in sources {
            let endpoint = source.endpoint.clone();
            let source_identity = source.source_identity.clone();
            let kind = source.kind;
            let at_daa_score = source.head.at_daa_score;
            let response = timeout(
                RPC_CALL_TIMEOUT,
                source.client.get_consensus_atomic_state_hash(GetConsensusAtomicStateHashRequest { block_hash }),
            )
            .await;

            match response {
                Ok(Ok(response)) => match response.state_hash {
                    Some(state_hash_hex) => match decode_hash32_hex(&state_hash_hex) {
                        Ok(state_hash) => evidence.push(SnapshotSupportEvidence {
                            source_identity,
                            source_label: endpoint.clone(),
                            snapshot_id: hex_encode(state_hash),
                            kind,
                            at_daa_score,
                            at_block_hash: block_hash.to_string(),
                        }),
                        Err(err) => {
                            self.record_source_failure(&endpoint).await;
                            trace!(
                                "[atomic-bootstrap] getConsensusAtomicStateHash from {} returned invalid hash for {}: {}",
                                endpoint,
                                block_hash,
                                err
                            );
                        }
                    },
                    None => {
                        trace!("[atomic-bootstrap] getConsensusAtomicStateHash from {} had no state for {}", endpoint, block_hash);
                    }
                },
                Ok(Err(err)) => {
                    self.record_source_failure(&endpoint).await;
                    trace!("[atomic-bootstrap] getConsensusAtomicStateHash failed on {}: {err}", endpoint);
                }
                Err(_) => {
                    self.record_source_failure(&endpoint).await;
                    trace!("[atomic-bootstrap] getConsensusAtomicStateHash timeout on {}", endpoint);
                }
            }

            let _ = source.client.disconnect().await;
        }

        if evidence.is_empty() {
            return Err(format!("no compatible bootstrap source reported consensus atomic state for `{block_hash}`"));
        }

        let quorum_policy = self.snapshot_quorum_policy();
        let decision = select_snapshot_quorum(
            evidence,
            quorum_policy.allow_peer_majority_fallback,
            quorum_policy.require_seed_confirmed_if_any_seed,
            quorum_policy.seed_confirmed_min_non_seed_sources,
            quorum_policy.peer_majority_min_sources,
        )
        .map_err(|err| format!("atomic consensus state hash quorum unavailable for `{block_hash}`: {err}"))?;

        if decision.snapshot_id != expected_state_hash_hex {
            return Err(format!(
                "atomic consensus state hash quorum selected `{}`, expected `{}` for `{}` using {}",
                decision.snapshot_id, expected_state_hash_hex, block_hash, decision.policy_description
            ));
        }

        trace!(
            "[atomic-bootstrap] verified consensus atomic state hash {} for {} using {}",
            expected_state_hash_hex,
            block_hash,
            decision.policy_description
        );
        Ok(())
    }

    async fn verify_consensus_atomic_state_hash_p2p_quorum(
        &self,
        block_hash: BlockHash,
        expected_state_hash: [u8; 32],
        anchor_daa_score: Option<u64>,
    ) -> Result<(), String> {
        let anchor_daa_score = match anchor_daa_score {
            Some(anchor_daa_score) => anchor_daa_score,
            None => {
                let consensus = self.flow_context.consensus();
                let session = consensus.session().await;
                session
                    .async_get_header(block_hash)
                    .await
                    .map_err(|err| format!("local header unavailable for P2P Atomic state hash quorum `{block_hash}`: {err}"))?
                    .daa_score
            }
        };
        let decision = self.select_p2p_atomic_state_hash_quorum(block_hash, anchor_daa_score).await?;
        let expected_state_hash_hex = hex_encode(expected_state_hash);
        if decision.snapshot_id != expected_state_hash_hex {
            return Err(format!(
                "P2P atomic consensus state hash quorum selected `{}`, expected `{}` for `{}` using {}",
                decision.snapshot_id, expected_state_hash_hex, block_hash, decision.policy_description
            ));
        }

        info!(
            "[atomic-bootstrap:p2p] verified Atomic state hash {} for {} using {}",
            expected_state_hash_hex, block_hash, decision.policy_description
        );
        Ok(())
    }

    async fn select_p2p_atomic_state_hash_quorum(
        &self,
        block_hash: BlockHash,
        anchor_daa_score: u64,
    ) -> Result<SnapshotQuorumDecision, String> {
        let min_sources = self.p2p_atomic_quorum_min_sources()?;
        let sample_limit = Self::p2p_audit_sample_limit(min_sources);
        let evidence = self.collect_p2p_atomic_state_hash_evidence(block_hash, anchor_daa_score, sample_limit).await;
        if evidence.is_empty() {
            return Err(format!("no active P2P peer reported consensus atomic state for `{block_hash}` at daa {anchor_daa_score}"));
        }

        select_snapshot_quorum(evidence, true, false, min_sources, min_sources).map_err(|err| {
            format!("P2P atomic consensus state hash quorum unavailable for `{block_hash}` at daa {anchor_daa_score}: {err}")
        })
    }

    fn p2p_atomic_quorum_min_sources(&self) -> Result<usize, String> {
        if self.disable_dns_seed_sources && !self.allow_peer_majority_fallback_override {
            return Err("P2P peer-only Atomic quorum disabled by policy: --nodnsseed requires --atomic-bootstrap-allow-peer-fallback"
                .to_string());
        }

        Ok(if self.disable_dns_seed_sources {
            self.peer_majority_min_sources.max(1)
        } else {
            self.seed_confirmed_min_non_seed_sources.max(1)
        })
    }

    fn p2p_audit_sample_limit(min_sources: usize) -> usize {
        min_sources
            .saturating_mul(2)
            .saturating_add(1)
            .max(P2P_AUDIT_MIN_SAMPLE_SOURCES)
            .min(P2P_AUDIT_MAX_SAMPLE_SOURCES)
            .max(min_sources)
            .min(MAX_REMOTE_SOURCES)
    }

    fn select_p2p_audit_peer_sample(&self, block_hash: BlockHash, sample_limit: usize) -> (usize, usize, Vec<P2pAuditPeerCandidate>) {
        let routers = self.flow_context.active_peer_routers();
        let active_peer_count = routers.len();
        let mut candidates = Vec::new();

        for router in routers.into_iter().take(MAX_REMOTE_SOURCES) {
            let properties = router.properties();
            if !properties.atomic_enabled {
                continue;
            }

            let source_identity = properties.unified_node_id.map(hex_encode).unwrap_or_else(|| router.key().to_string());
            let score = p2p_audit_sample_score(block_hash, &source_identity);
            candidates.push((score, P2pAuditPeerCandidate { router, source_identity }));
        }

        let atomic_peer_count = candidates.len();
        candidates.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.source_identity.cmp(&b.1.source_identity)));
        let sample = candidates.into_iter().take(sample_limit).map(|(_, candidate)| candidate).collect();
        (active_peer_count, atomic_peer_count, sample)
    }

    async fn collect_p2p_atomic_state_hash_evidence(
        &self,
        block_hash: BlockHash,
        anchor_daa_score: u64,
        sample_limit: usize,
    ) -> Vec<SnapshotSupportEvidence> {
        let (active_peer_count, atomic_peer_count, peer_sample) = self.select_p2p_audit_peer_sample(block_hash, sample_limit);
        let mut tasks = Vec::new();

        for candidate in peer_sample {
            let router = candidate.router;
            let source_identity = candidate.source_identity;
            tasks.push(async move {
                let router_label = router.to_string();
                let result = self.request_p2p_atomic_state_hash(router.clone(), block_hash, anchor_daa_score).await;
                (router_label, source_identity, result)
            });
        }

        let mut evidence = Vec::new();
        for (router_label, source_identity, result) in join_all(tasks).await {
            match result {
                Ok(Some(state_hash)) => evidence.push(SnapshotSupportEvidence {
                    source_identity,
                    source_label: router_label,
                    snapshot_id: hex_encode(state_hash),
                    kind: SourceKind::Peer,
                    at_daa_score: anchor_daa_score,
                    at_block_hash: block_hash.to_string(),
                }),
                Ok(None) => {
                    trace!("[atomic-bootstrap:p2p] peer {} has no consensus Atomic state for {}", router_label, block_hash);
                }
                Err(err) => {
                    info!("[atomic-bootstrap:p2p] peer {} consensus Atomic state hash request failed: {}", router_label, err);
                }
            }
        }

        if evidence.is_empty() {
            trace!(
                "[atomic-bootstrap:p2p] Atomic state hash evidence for {}: 0 responding Atomic peer(s), {} active peer(s), {} Atomic-capable peer(s)",
                block_hash,
                active_peer_count,
                atomic_peer_count
            );
        } else {
            trace!(
                "[atomic-bootstrap:p2p] Atomic state hash evidence for {}: {} responding Atomic peer(s), {} active peer(s), {} Atomic-capable peer(s)",
                block_hash,
                evidence.len(),
                active_peer_count,
                atomic_peer_count
            );
        }
        evidence
    }

    async fn collect_p2p_atomic_token_state_hash_evidence(
        &self,
        block_hash: BlockHash,
        anchor_daa_score: u64,
        sample_limit: usize,
    ) -> Vec<SnapshotSupportEvidence> {
        let (active_peer_count, atomic_peer_count, peer_sample) = self.select_p2p_audit_peer_sample(block_hash, sample_limit);
        let mut tasks = Vec::new();

        for candidate in peer_sample {
            let router = candidate.router;
            let source_identity = candidate.source_identity;
            tasks.push(async move {
                let router_label = router.to_string();
                let result = self.request_p2p_atomic_token_state_hash(router.clone(), block_hash, anchor_daa_score).await;
                (router_label, source_identity, result)
            });
        }

        let mut evidence = Vec::new();
        for (router_label, source_identity, result) in join_all(tasks).await {
            match result {
                Ok(Some(state_hash)) => evidence.push(SnapshotSupportEvidence {
                    source_identity,
                    source_label: router_label,
                    snapshot_id: hex_encode(state_hash),
                    kind: SourceKind::Peer,
                    at_daa_score: anchor_daa_score,
                    at_block_hash: block_hash.to_string(),
                }),
                Ok(None) => {
                    trace!("[atomic-bootstrap:p2p] peer {} has no healthy Atomic token state for {}", router_label, block_hash);
                }
                Err(err) => {
                    info!("[atomic-bootstrap:p2p] peer {} Atomic token state hash request failed: {}", router_label, err);
                }
            }
        }

        if evidence.is_empty() {
            trace!(
                "[atomic-bootstrap:p2p] Atomic token state hash evidence for {}: 0 responding healthy Atomic peer(s), {} active peer(s), {} Atomic-capable peer(s)",
                block_hash,
                active_peer_count,
                atomic_peer_count
            );
        } else {
            trace!(
                "[atomic-bootstrap:p2p] Atomic token state hash evidence for {}: {} responding healthy Atomic peer(s), {} active peer(s), {} Atomic-capable peer(s)",
                block_hash,
                evidence.len(),
                active_peer_count,
                atomic_peer_count
            );
        }
        evidence
    }

    async fn request_p2p_atomic_state_hash(
        &self,
        router: Arc<Router>,
        block_hash: BlockHash,
        anchor_daa_score: u64,
    ) -> Result<Option<[u8; 32]>, String> {
        let mut route = router.subscribe_response_only();
        let route_id = route.id();
        let result = async {
            router
                .enqueue(make_request!(
                    Payload::RequestConsensusAtomicStateHash,
                    RequestConsensusAtomicStateHashMessage { block_hash: Some(block_hash.into()), anchor_daa_score },
                    route_id
                ))
                .await
                .map_err(|err| format!("send failed: {err}"))?;

            let message = timeout(P2P_ATOMIC_STATE_HASH_TIMEOUT, route.recv())
                .await
                .map_err(|_| format!("timed out after {}s", P2P_ATOMIC_STATE_HASH_TIMEOUT.as_secs()))?
                .ok_or_else(|| "response route closed".to_string())?;

            let Some(Payload::ConsensusAtomicStateHash(response)) = message.payload else {
                return Err("unexpected P2P response while waiting for ConsensusAtomicStateHash".to_string());
            };

            let Some(response_block_hash) = response.block_hash else {
                return Err("ConsensusAtomicStateHash response missing block hash".to_string());
            };
            let response_block_hash: BlockHash = response_block_hash.try_into().map_err(|err| format!("invalid block hash: {err}"))?;
            if response_block_hash != block_hash {
                return Err(format!("response block hash mismatch: expected `{block_hash}`, got `{response_block_hash}`"));
            }
            if response.anchor_daa_score != anchor_daa_score {
                return Err(format!(
                    "response DAA mismatch for `{block_hash}`: expected {}, got {}",
                    anchor_daa_score, response.anchor_daa_score
                ));
            }
            if !response.has_state {
                return Ok(None);
            }
            if response.state_hash.len() != 32 {
                return Err(format!("invalid state hash length: {}", response.state_hash.len()));
            }
            let mut state_hash = [0u8; 32];
            state_hash.copy_from_slice(&response.state_hash);
            Ok(Some(state_hash))
        }
        .await;
        router.unsubscribe_route_id(route_id);
        result
    }

    async fn request_p2p_atomic_token_state_hash(
        &self,
        router: Arc<Router>,
        block_hash: BlockHash,
        anchor_daa_score: u64,
    ) -> Result<Option<[u8; 32]>, String> {
        let mut route = router.subscribe_response_only();
        let route_id = route.id();
        let result = async {
            router
                .enqueue(make_request!(
                    Payload::RequestAtomicTokenStateHash,
                    RequestAtomicTokenStateHashMessage { block_hash: Some(block_hash.into()), anchor_daa_score },
                    route_id
                ))
                .await
                .map_err(|err| format!("send failed: {err}"))?;

            let message = timeout(P2P_ATOMIC_STATE_HASH_TIMEOUT, route.recv())
                .await
                .map_err(|_| format!("timed out after {}s", P2P_ATOMIC_STATE_HASH_TIMEOUT.as_secs()))?
                .ok_or_else(|| "response route closed".to_string())?;

            let Some(Payload::AtomicTokenStateHash(response)) = message.payload else {
                return Err("unexpected P2P response while waiting for AtomicTokenStateHash".to_string());
            };

            let Some(response_block_hash) = response.block_hash else {
                return Err("AtomicTokenStateHash response missing block hash".to_string());
            };
            let response_block_hash: BlockHash = response_block_hash.try_into().map_err(|err| format!("invalid block hash: {err}"))?;
            if response_block_hash != block_hash {
                return Err(format!("response block hash mismatch: expected `{block_hash}`, got `{response_block_hash}`"));
            }
            if response.anchor_daa_score != anchor_daa_score {
                return Err(format!(
                    "response DAA mismatch for `{block_hash}`: expected {}, got {}",
                    anchor_daa_score, response.anchor_daa_score
                ));
            }
            if !response.has_state {
                return Ok(None);
            }
            if response.state_hash.len() != 32 {
                return Err(format!("invalid state hash length: {}", response.state_hash.len()));
            }
            let mut state_hash = [0u8; 32];
            state_hash.copy_from_slice(&response.state_hash);
            Ok(Some(state_hash))
        }
        .await;
        router.unsubscribe_route_id(route_id);
        result
    }

    async fn audit_healthy_state_with_p2p(&self, health: &AtomicTokenHealth) -> Result<bool, String> {
        if health.runtime_state != AtomicTokenRuntimeState::Healthy || health.is_degraded || health.bootstrap_in_progress {
            self.log_pending_audit(
                "local_token_index_not_ready",
                format!(
                    "[atomic-bootstrap:p2p] audit result: status=pending scope=token reason=local_token_index_not_ready runtime={} degraded={} bootstrap_in_progress={}",
                health.runtime_state.as_str(),
                health.is_degraded,
                    health.bootstrap_in_progress
                ),
            )
            .await;
            return Ok(false);
        }

        let active_peer_count = self.flow_context.active_peer_routers().len();
        if active_peer_count == 0 {
            info!("[atomic-bootstrap:p2p] audit result: status=skipped scope=token reason=no_active_p2p_peers");
            return Ok(false);
        }

        let (context, anchor_daa_score) = match self.atomic_token_service.get_p2p_audit_context().await {
            Ok(Some(value)) => value,
            Ok(None) => {
                if !self.audit_context_revalidation_attempted.swap(true, Ordering::SeqCst) {
                    info!(
                        "[atomic-bootstrap:p2p] no retained token audit checkpoint is available after catch-up; refreshing retained checkpoint hashes once before deferring"
                    );
                    let refreshed_context = match self.atomic_token_service.revalidate_retained_state_for_audit_once().await {
                        Ok(repaired) => {
                            if repaired {
                                info!(
                                    "[atomic-bootstrap:p2p] local retained-chain checkpoint refresh completed; retrying token audit context"
                                );
                            } else {
                                info!(
                                    "[atomic-bootstrap:p2p] local retained-chain checkpoint refresh found no persisted repair; retrying token audit context"
                                );
                            }
                            match self.atomic_token_service.get_p2p_audit_context().await {
                                Ok(Some(value)) => Some(value),
                                Ok(None) => {
                                    self.log_pending_audit(
                                        "no_finality_stable_revalidated_token_checkpoint_after_local_refresh",
                                        "[atomic-bootstrap:p2p] audit result: status=pending scope=token reason=no_finality_stable_revalidated_token_checkpoint_after_local_refresh action=wait_for_new_finality_stable_checkpoint".to_string(),
                                    )
                                    .await;
                                    return Ok(false);
                                }
                                Err(err) => {
                                    self.log_pending_audit(
                                        "stable_token_audit_anchor_unavailable_after_local_refresh",
                                        format!(
                                            "[atomic-bootstrap:p2p] audit result: status=pending scope=token reason=stable_token_audit_anchor_unavailable_after_local_refresh detail=\"{}\"",
                                            err
                                        ),
                                    )
                                    .await;
                                    return Ok(false);
                                }
                            }
                        }
                        Err(err) => {
                            warn!(
                                "[atomic-bootstrap:p2p] local retained-chain checkpoint refresh failed while preparing token audit: {err}"
                            );
                            None
                        }
                    };
                    if let Some(value) = refreshed_context {
                        value
                    } else {
                        self.log_pending_audit(
                            "no_finality_stable_revalidated_token_checkpoint",
                            "[atomic-bootstrap:p2p] audit result: status=pending scope=token reason=no_finality_stable_revalidated_token_checkpoint action=wait_for_atomic_catchup_or_revalidation".to_string(),
                        )
                        .await;
                        return Ok(false);
                    }
                } else {
                    self.log_pending_audit(
                        "no_finality_stable_revalidated_token_checkpoint",
                        "[atomic-bootstrap:p2p] audit result: status=pending scope=token reason=no_finality_stable_revalidated_token_checkpoint action=wait_for_atomic_catchup_or_revalidation".to_string(),
                    )
                    .await;
                    return Ok(false);
                }
            }
            Err(err) => {
                self.log_pending_audit(
                    "stable_token_audit_anchor_unavailable",
                    format!(
                        "[atomic-bootstrap:p2p] audit result: status=pending scope=token reason=stable_token_audit_anchor_unavailable detail=\"{}\"",
                        err
                    ),
                )
                .await;
                return Ok(false);
            }
        };
        let anchor_hash = context.at_block_hash;
        let Some(local_state_hash) = self.local_consensus_p2p_token_audit_hash(anchor_hash).await? else {
            self.log_pending_audit(
                "local_consensus_token_audit_hash_unavailable",
                format!(
                    "[atomic-bootstrap:p2p] audit result: status=pending scope=token reason=local_consensus_token_audit_hash_unavailable anchor={} daa={} action=run_consensus_only_audit token_verified=false",
                    anchor_hash, anchor_daa_score
                ),
            )
            .await;
            return self.audit_healthy_consensus_state_with_p2p(anchor_hash, anchor_daa_score).await;
        };
        let local_state_hash_hex = hex_encode(local_state_hash);

        let min_sources = self.p2p_atomic_quorum_min_sources()?;
        let sample_limit = Self::p2p_audit_sample_limit(min_sources);
        let evidence = self.collect_p2p_atomic_token_state_hash_evidence(anchor_hash, anchor_daa_score, sample_limit).await;
        let matching_local_sources = evidence.iter().filter(|entry| entry.snapshot_id == local_state_hash_hex).count();
        let evidence_summary = snapshot_evidence_summary(&evidence);
        if matching_local_sources >= min_sources {
            info!(
                "[atomic-bootstrap:p2p] audit result: status=passed scope=token reason=token_checkpoint_matched anchor={} daa={} local_hash={} policy=\"local-token-root confirmed by independent peers (minimum independent non-seed sources: {}, matching local sources: {}, total peer responses: {})\" runtime={} active_peers={} evidence={}",
                anchor_hash,
                anchor_daa_score,
                local_state_hash_hex,
                min_sources,
                matching_local_sources,
                evidence.len(),
                health.runtime_state.as_str(),
                active_peer_count,
                evidence_summary
            );
            return Ok(true);
        }

        self.log_pending_audit(
            "peer_token_checkpoint_unavailable",
            format!(
                "[atomic-bootstrap:p2p] audit result: status=pending scope=token reason=local_token_checkpoint_not_confirmed anchor={} daa={} local_hash={} matching_local_sources={} required_sources={} total_peer_responses={} action=run_consensus_only_audit token_verified=false evidence={}",
                anchor_hash,
                anchor_daa_score,
                local_state_hash_hex,
                matching_local_sources,
                min_sources,
                evidence.len(),
                evidence_summary
            ),
        )
        .await;

        if matching_local_sources == 0 {
            if let Err(err) = self.atomic_token_service.log_p2p_audit_debug_at_block(anchor_hash).await {
                info!(
                    "[atomic-bootstrap:p2p] local Atomic token index debug unavailable at DAA-rendezvous block {} (daa={}): {}",
                    anchor_hash, anchor_daa_score, err
                );
            }
        }

        self.audit_healthy_consensus_state_with_p2p(anchor_hash, anchor_daa_score).await
    }

    async fn local_consensus_p2p_token_audit_hash(&self, block_hash: BlockHash) -> Result<Option<[u8; 32]>, String> {
        let consensus = self.flow_context.consensus();
        let session = consensus.session().await;
        session
            .async_get_atomic_p2p_token_audit_hash(block_hash)
            .await
            .map_err(|err| format!("local consensus Atomic P2P token audit hash unavailable for `{block_hash}`: {err}"))
    }

    async fn audit_healthy_consensus_state_with_p2p(&self, anchor_hash: BlockHash, anchor_daa_score: u64) -> Result<bool, String> {
        let consensus = self.flow_context.consensus();
        let session = consensus.session().await;
        let Some(local_consensus_state_hash) = session
            .async_get_atomic_state_hash(anchor_hash)
            .await
            .map_err(|err| format!("local consensus Atomic state hash unavailable for `{anchor_hash}`: {err}"))?
        else {
            info!(
                "[atomic-bootstrap:p2p] audit result: status=skipped scope=consensus_only reason=local_consensus_atomic_state_hash_unavailable anchor={} daa={} token_verified=false",
                anchor_hash, anchor_daa_score
            );
            return Ok(false);
        };

        let decision = match self.select_p2p_atomic_state_hash_quorum(anchor_hash, anchor_daa_score).await {
            Ok(decision) => decision,
            Err(err) => {
                info!(
                    "[atomic-bootstrap:p2p] audit result: status=skipped scope=consensus_only reason=peer_consensus_state_unavailable anchor={} daa={} token_verified=false detail=\"{}\"",
                    anchor_hash, anchor_daa_score, err
                );
                return Ok(false);
            }
        };

        let local_consensus_state_hash_hex = hex_encode(local_consensus_state_hash);
        if decision.snapshot_id == local_consensus_state_hash_hex {
            info!(
                "[atomic-bootstrap:p2p] audit result: status=passed scope=consensus_only reason=consensus_state_hash_matched anchor={} daa={} local_hash={} policy=\"{}\" token_verified=false action=wait_for_token_audit_pass",
                anchor_hash, anchor_daa_score, local_consensus_state_hash_hex, decision.policy_description
            );
            return Ok(true);
        }

        let reason = format!(
            "audit result: status=failed scope=consensus_only reason=consensus_state_hash_mismatch anchor={} daa={} local_hash={} quorum_hash={} policy=\"{}\" token_verified=false",
            anchor_hash, anchor_daa_score, local_consensus_state_hash_hex, decision.snapshot_id, decision.policy_description
        );
        warn!("[atomic-bootstrap:p2p] {reason}");
        warn!(
            "[atomic-bootstrap:p2p] audit action: scope=consensus_only result=no_atomic_index_degrade reason=consensus_only_mismatch_normal_p2p_consensus_remains_authoritative"
        );
        Ok(false)
    }

    async fn audit_healthy_state_with_sources(
        &self,
        sources: Vec<SourceClient>,
        protocol_version: u32,
        network_id: &str,
    ) -> Result<Option<BootstrapSelection>, String> {
        let source_count = sources.len();
        let quorum_policy = self.snapshot_quorum_policy();
        let (selected_snapshot_id, mut selected_sources, required_votes, policy_description) =
            match self.select_snapshot_sources(sources, quorum_policy) {
                Ok(selection) => selection,
                Err(err) => {
                    trace!("[atomic-bootstrap] healthy-state audit skipped: {err}");
                    return Ok(None);
                }
            };

        if selected_sources.len() < source_count {
            trace!(
                "[atomic-bootstrap] healthy-state audit selected snapshot {} from {}/{} compatible sources",
                selected_snapshot_id,
                selected_sources.len(),
                source_count
            );
        }

        let manifest_bytes =
            match self.fetch_manifest_bytes_with_quorum(&mut selected_sources, &selected_snapshot_id, required_votes).await {
                Ok(bytes) => bytes,
                Err(err) => {
                    for source in selected_sources {
                        let _ = source.client.disconnect().await;
                    }
                    trace!(
                        "[atomic-bootstrap] healthy-state audit skipped: manifest quorum unavailable for snapshot {}: {}",
                        selected_snapshot_id,
                        err
                    );
                    return Ok(None);
                }
            };

        let manifest = match SnapshotManifestV2::try_from_slice(&manifest_bytes) {
            Ok(manifest) => manifest,
            Err(err) => {
                for source in selected_sources {
                    let _ = source.client.disconnect().await;
                }
                trace!(
                    "[atomic-bootstrap] healthy-state audit skipped: manifest decode failed for snapshot {}: {}",
                    selected_snapshot_id,
                    err
                );
                return Ok(None);
            }
        };
        let expected_snapshot_id = hex_encode(snapshot_id_from_manifest(&manifest_bytes));
        if manifest.protocol_version as u32 != protocol_version
            || manifest.network_id != network_id
            || expected_snapshot_id != selected_snapshot_id
        {
            for source in selected_sources {
                let _ = source.client.disconnect().await;
            }
            trace!("[atomic-bootstrap] healthy-state audit skipped: manifest metadata mismatch for snapshot {}", selected_snapshot_id);
            return Ok(None);
        }
        if let Err(err) = self.validate_manifest_sanity(&manifest) {
            for source in selected_sources {
                let _ = source.client.disconnect().await;
            }
            trace!(
                "[atomic-bootstrap] healthy-state audit skipped: manifest sanity validation failed for snapshot {}: {}",
                selected_snapshot_id,
                err
            );
            return Ok(None);
        }

        let anchor_hash = BlockHash::from_bytes(manifest.at_block_hash);
        let quorum_state_hash = manifest.state_hash_at_fp;

        let Some(local_state_hash) = self.atomic_token_service.get_state_hash_at_block(anchor_hash).await else {
            for source in selected_sources {
                let _ = source.client.disconnect().await;
            }
            trace!(
                "[atomic-bootstrap] healthy-state audit skipped: local node has no retained state hash for finalized anchor {}",
                anchor_hash
            );
            return Ok(None);
        };

        if local_state_hash == quorum_state_hash {
            for source in selected_sources {
                let _ = source.client.disconnect().await;
            }
            trace!("[atomic-bootstrap] healthy-state audit passed at anchor {} using {}", anchor_hash, policy_description);
            return Ok(None);
        }

        warn!(
            "[atomic-bootstrap] healthy-state audit mismatch at anchor {}: local state hash {} differs from verified manifest {}",
            anchor_hash,
            hex_encode(local_state_hash),
            hex_encode(quorum_state_hash)
        );
        warn!(
            "[atomic-bootstrap] healthy-state audit detected divergence candidate; triggering verified recovery bootstrap before fail-closed decision"
        );

        Ok(Some(BootstrapSelection {
            snapshot_id: selected_snapshot_id,
            sources: selected_sources,
            required_votes,
            policy_description,
        }))
    }

    async fn run_verified_bootstrap(
        &self,
        protocol_version: u32,
        network_id: &str,
        selection: BootstrapSelection,
    ) -> Result<bool, String> {
        let BootstrapSelection { snapshot_id, mut sources, required_votes, policy_description: _ } = selection;

        let bootstrap_result: Result<bool, String> = async {
            info!(
                "[atomic-bootstrap] fetching verified snapshot manifest {} from {} candidate source(s), required votes={}",
                snapshot_id,
                sources.len(),
                required_votes
            );
            let manifest_bytes = self.fetch_manifest_bytes_with_quorum(&mut sources, &snapshot_id, required_votes).await?;
            let manifest = SnapshotManifestV2::try_from_slice(&manifest_bytes)
                .map_err(|err| format!("snapshot manifest decode failed: {err}"))?;

            if manifest.protocol_version as u32 != protocol_version {
                return Err(format!(
                    "snapshot manifest protocol mismatch: expected {}, got {}",
                    protocol_version, manifest.protocol_version
                ));
            }
            if manifest.network_id != network_id {
                return Err(format!("snapshot manifest network mismatch: expected `{network_id}`, got `{}`", manifest.network_id));
            }

            let expected_snapshot_id = hex_encode(snapshot_id_from_manifest(&manifest_bytes));
            if expected_snapshot_id != snapshot_id {
                return Err(format!("snapshot id mismatch: selected `{snapshot_id}` but manifest computes `{expected_snapshot_id}`"));
            }

            self.validate_manifest_sanity(&manifest)?;
            info!(
                "[atomic-bootstrap] verified snapshot manifest {}: anchor={}, daa={}, snapshot={} bytes/{} chunk(s), replay={} bytes/{} chunk(s)",
                snapshot_id,
                hex_encode(manifest.at_block_hash),
                manifest.at_daa_score,
                manifest.snapshot_file_size,
                manifest.snapshot_chunk_hashes.len(),
                manifest.replay_window_size,
                manifest.replay_window_chunk_hashes.len()
            );

            let download_dir = self.atomic_data_dir.join("bootstrap").join("download");
            std::fs::create_dir_all(&download_dir)
                .map_err(|err| format!("failed creating bootstrap download directory `{}`: {err}", download_dir.display()))?;

            let snapshot_path = download_dir.join(&manifest.snapshot_file_name);
            let manifest_path = PathBuf::from(format!("{}.manifest", snapshot_path.display()));
            let replay_path = snapshot_path.with_extension("replay.bin");

            self.download_and_verify_snapshot_to_file(&sources, &snapshot_id, &manifest, &snapshot_path).await?;
            self.download_and_verify_replay_window_to_file(&sources, &snapshot_id, &manifest, &replay_path).await?;
            std::fs::write(&manifest_path, &manifest_bytes)
                .map_err(|err| format!("failed writing snapshot manifest `{}`: {err}", manifest_path.display()))?;

            info!(
                "[atomic-bootstrap] importing verified Atomic snapshot {}: anchor={}, daa={}",
                snapshot_id,
                hex_encode(manifest.at_block_hash),
                manifest.at_daa_score
            );
            self.atomic_token_service
                .import_snapshot_from_file(&snapshot_path)
                .await
                .map_err(|err| format!("snapshot import failed: {err}"))?;
            info!("[atomic-bootstrap] verified Atomic snapshot {} imported successfully", snapshot_id);

            Ok(true)
        }
        .await;

        for source in sources {
            let _ = source.client.disconnect().await;
        }

        bootstrap_result
    }

    async fn try_bootstrap_once(&self) -> Result<bool, String> {
        let _attempt_guard = self.bootstrap_attempt_lock.lock().await;
        self.try_bootstrap_once_inner().await
    }

    async fn try_bootstrap_once_inner(&self) -> Result<bool, String> {
        let effective_health = self.atomic_token_service.get_health().await;
        let health = self.atomic_token_service.get_local_health().await;
        if health.runtime_state == AtomicTokenRuntimeState::NotReady && !self.flow_context.is_payload_hf_active() {
            trace!("[atomic-bootstrap] bootstrap deferred until payload hardfork is active locally");
            return Ok(false);
        }
        if health.bootstrap_in_progress {
            trace!("[atomic-bootstrap:p2p] local Atomic replay/import already in progress; skipping optional snapshot bootstrap");
            return Ok(false);
        }
        if self.flow_context.is_ibd_running() {
            info!(
                "[atomic-bootstrap:p2p] bootstrap deferred while P2P IBD is running; Atomic state will be recovered through pruning-point state sync/local replay"
            );
            return Ok(false);
        }
        if effective_health.runtime_state == AtomicTokenRuntimeState::Recovering
            && health.runtime_state == AtomicTokenRuntimeState::Healthy
            && !health.is_degraded
            && self.configured_rpc_peers.is_empty()
        {
            self.log_pending_audit(
                "local_token_index_catching_up",
                format!(
                    "[atomic-bootstrap:p2p] audit result: status=pending scope=token reason=local_token_index_catching_up action=wait_for_atomic_catchup runtime={} local_runtime={}",
                    effective_health.runtime_state.as_str(),
                    health.runtime_state.as_str()
                ),
            )
            .await;
            return Ok(false);
        }
        let should_audit_healthy_state = if !health.is_degraded
            && health.runtime_state == AtomicTokenRuntimeState::Healthy
            && effective_health.runtime_state == AtomicTokenRuntimeState::Healthy
            && health.last_applied_block.is_some()
        {
            if !self.should_run_health_audit().await {
                return Ok(false);
            }
            true
        } else {
            false
        };

        if should_audit_healthy_state {
            match self.audit_healthy_state_with_p2p(&health).await {
                Ok(true) => return Ok(false),
                Ok(false) => {}
                Err(err) if self.configured_rpc_peers.is_empty() => return Err(err),
                Err(err) => {
                    warn!(
                        "[atomic-bootstrap:p2p] healthy-state audit failed; trying optional RPC snapshot audit before repair decision: {err}"
                    );
                }
            }
        }

        if effective_health.runtime_state == AtomicTokenRuntimeState::Recovering
            && health.runtime_state != AtomicTokenRuntimeState::Healthy
            && !health.is_degraded
            && self.configured_rpc_peers.is_empty()
        {
            info!(
                "[atomic-bootstrap:p2p] Atomic state is recovering; healthy-state P2P audit deferred until local replay reaches a stable healthy state"
            );
            return Ok(false);
        }
        let mut local_repair_error = None;
        if health.runtime_state == AtomicTokenRuntimeState::NotReady {
            match self.atomic_token_service.repair_from_local_selected_chain_once().await {
                Ok(true) => {
                    info!(
                        "[atomic-bootstrap] Atomic state repaired by local selected-chain replay/backfill; remote snapshot bootstrap not needed"
                    );
                    return Ok(true);
                }
                Ok(false) => {}
                Err(err) => {
                    trace!("[atomic-bootstrap] local selected-chain Atomic repair is not available yet: {err}");
                    local_repair_error = Some(err.to_string());
                }
            }
        }

        let protocol_version = self.atomic_token_service.protocol_version() as u32;
        let network_id = self.atomic_token_service.network_id().to_string();
        let mut sources = self.collect_compatible_sources(protocol_version, &network_id).await;

        let mut retained_revalidation_error = None;
        if health.runtime_state == AtomicTokenRuntimeState::Degraded && sources.is_empty() {
            match self.atomic_token_service.revalidate_retained_state_once().await {
                Ok(true) => {
                    info!(
                        "[atomic-bootstrap] degraded Atomic state repaired by local retained-chain revalidation; remote snapshot bootstrap not needed"
                    );
                    return Ok(true);
                }
                Ok(false) => {
                    info!(
                        "[atomic-bootstrap] degraded Atomic state has no retained verified chain state for local revalidation; remote snapshot bootstrap is required"
                    );
                    retained_revalidation_error = Some("no retained Atomic state is available for local revalidation".to_string());
                }
                Err(err) => {
                    warn!(
                        "[atomic-bootstrap] local retained-chain revalidation failed while Atomic is degraded: {err}; remote snapshot bootstrap is required"
                    );
                    retained_revalidation_error = Some(err.to_string());
                }
            }
            if health.runtime_state == AtomicTokenRuntimeState::Degraded {
                sources = self.collect_compatible_sources(protocol_version, &network_id).await;
            }
        } else if health.runtime_state == AtomicTokenRuntimeState::Degraded {
            info!("[atomic-bootstrap] degraded Atomic state has compatible remote source(s); using snapshot bootstrap before local retained-chain repair");
        }

        if sources.is_empty() {
            let mut reason = self.no_sources_reason();
            if let Some(local_err) = local_repair_error {
                reason.push_str("; local selected-chain replay/backfill also failed: ");
                reason.push_str(&local_err);
            }
            if let Some(local_err) = retained_revalidation_error {
                reason.push_str("; local retained-chain revalidation also failed: ");
                reason.push_str(&local_err);
            }
            if should_audit_healthy_state {
                trace!("[atomic-bootstrap] healthy-state audit skipped: {reason}");
                return Ok(false);
            }
            if health.runtime_state == AtomicTokenRuntimeState::NotReady
                && !health.is_degraded
                && (self.flow_context.is_ibd_running() || health.last_applied_block.is_none())
            {
                info!(
                    "[atomic-bootstrap] Atomic state is not ready yet; waiting for local block replay/IBD or a compatible snapshot source ({reason})"
                );
                return Ok(false);
            }
            if health.runtime_state == AtomicTokenRuntimeState::NotReady && !health.is_degraded && self.configured_rpc_peers.is_empty()
            {
                trace!(
                    "[atomic-bootstrap] optional RPC snapshot bootstrap skipped while Atomic state is not ready yet; waiting for local replay or P2P pruning-point Atomic state sync ({reason})"
                );
                return Ok(false);
            }
            if !health.is_degraded && self.configured_rpc_peers.is_empty() {
                trace!(
                    "[atomic-bootstrap] optional RPC snapshot bootstrap skipped while Atomic state is {}; local replay/P2P sync remains authoritative ({reason})",
                    health.runtime_state.as_str()
                );
                return Ok(false);
            }
            return self.defer_and_retry(&reason).await;
        }

        if should_audit_healthy_state {
            let Some(selection) = self.audit_healthy_state_with_sources(sources, protocol_version, &network_id).await? else {
                return Ok(false);
            };

            info!(
                "[atomic-bootstrap] healthy-state audit requested verified recovery bootstrap for snapshot {} using {}",
                selection.snapshot_id, selection.policy_description
            );

            match self.run_verified_bootstrap(protocol_version, &network_id, selection).await {
                Ok(applied) => {
                    if applied {
                        info!("[atomic-bootstrap] verified recovery bootstrap completed after divergence detection");
                    }
                    return Ok(applied);
                }
                Err(err) => {
                    let reason = format!("confirmed token-state divergence and verified recovery bootstrap failed: {err}");
                    self.atomic_token_service
                        .mark_degraded_and_persist(&reason)
                        .await
                        .map_err(|mark_err| format!("{reason}; failed marking degraded: {mark_err}"))?;
                    return Err(format!("{reason}; node marked degraded"));
                }
            }
        }

        let quorum_policy = self.snapshot_quorum_policy();

        let source_count = sources.len();
        let (selected_snapshot_id, selected_sources, required_votes, policy_description) =
            match self.select_snapshot_sources(sources, quorum_policy) {
                Ok(selection) => selection,
                Err(err) => return self.defer_and_retry(&err).await,
            };
        if selected_sources.len() < source_count {
            info!(
                "[atomic-bootstrap] selected snapshot {} from {}/{} compatible sources",
                selected_snapshot_id,
                selected_sources.len(),
                source_count
            );
        }
        info!("[atomic-bootstrap] using bootstrap policy: {policy_description}");
        self.run_verified_bootstrap(
            protocol_version,
            &network_id,
            BootstrapSelection { snapshot_id: selected_snapshot_id, sources: selected_sources, required_votes, policy_description },
        )
        .await
    }

    async fn defer_and_retry(&self, reason: &str) -> Result<bool, String> {
        warn!("[atomic-bootstrap] remote bootstrap unavailable: {reason}; refusing unsafe state and waiting for safe quorum retry");
        Ok(false)
    }

    fn candidate_endpoints(&self) -> Vec<CandidateEndpoint> {
        let mut endpoints = Vec::new();
        let mut by_endpoint = HashMap::<String, usize>::new();

        for address in &self.configured_rpc_peers {
            let socket = SocketAddr::new(address.ip.into(), address.port);
            let endpoint = format!("grpc://{socket}");
            push_candidate_endpoint(&mut endpoints, &mut by_endpoint, endpoint, None, SourceKind::Configured);
        }

        endpoints
    }

    fn select_snapshot_sources(
        &self,
        sources: Vec<SourceClient>,
        quorum_policy: SnapshotQuorumPolicy,
    ) -> Result<(String, Vec<SourceClient>, usize, String), String> {
        let evidence = sources
            .iter()
            .map(|source| SnapshotSupportEvidence {
                source_identity: source.source_identity.clone(),
                source_label: source.endpoint.clone(),
                snapshot_id: source.head.snapshot_id.to_ascii_lowercase(),
                kind: source.kind,
                at_daa_score: source.head.at_daa_score,
                at_block_hash: source.head.at_block_hash.to_string(),
            })
            .collect::<Vec<_>>();
        let decision = select_snapshot_quorum(
            evidence,
            quorum_policy.allow_peer_majority_fallback,
            quorum_policy.require_seed_confirmed_if_any_seed,
            quorum_policy.seed_confirmed_min_non_seed_sources,
            quorum_policy.peer_majority_min_sources,
        )?;
        let mut selected_sources: Vec<SourceClient> = Vec::new();
        let mut selected_by_identity = HashMap::<String, usize>::new();
        for source in sources.into_iter().filter(|source| source.head.snapshot_id.eq_ignore_ascii_case(&decision.snapshot_id)) {
            if let Some(existing_idx) = selected_by_identity.get(&source.source_identity).copied() {
                let merged_kind = merge_source_kind(selected_sources[existing_idx].kind, source.kind);
                let replace_existing = source_preferred_over(&source, &selected_sources[existing_idx]);
                if replace_existing {
                    let mut replacement = source;
                    replacement.kind = merged_kind;
                    selected_sources[existing_idx] = replacement;
                } else {
                    selected_sources[existing_idx].kind = merged_kind;
                }
                continue;
            }

            selected_by_identity.insert(source.source_identity.clone(), selected_sources.len());
            selected_sources.push(source);
        }
        if selected_sources.is_empty() {
            return Err(format!("no source client remained after snapshot selection for `{}`", decision.snapshot_id));
        }

        Ok((decision.snapshot_id, selected_sources, decision.required_votes, decision.policy_description))
    }

    async fn fetch_manifest_bytes_with_quorum(
        &self,
        sources: &mut [SourceClient],
        snapshot_id: &str,
        required_votes: usize,
    ) -> Result<Vec<u8>, String> {
        struct ManifestVote {
            manifest_bytes: Vec<u8>,
            vote_count: usize,
        }

        let mut votes: HashMap<[u8; 32], ManifestVote> = HashMap::new();
        let mut valid_responses = 0usize;
        let mut last_error = "manifest unavailable".to_string();

        for source in sources.iter_mut() {
            if self.is_source_blocked(&source.endpoint).await {
                continue;
            }

            let response = match timeout(RPC_CALL_TIMEOUT, source.client.get_sc_snapshot_manifest(snapshot_id.to_string())).await {
                Ok(Ok(response)) => response,
                Ok(Err(err)) => {
                    self.record_source_failure(&source.endpoint).await;
                    last_error = format!("{}: {err}", source.endpoint);
                    continue;
                }
                Err(_) => {
                    self.record_source_failure(&source.endpoint).await;
                    last_error = format!("{}: timeout", source.endpoint);
                    continue;
                }
            };

            if response.manifest_hex.len() > MAX_MANIFEST_HEX_LEN {
                self.record_source_failure(&source.endpoint).await;
                last_error = format!(
                    "{}: manifest hex length {} exceeds limit {}",
                    source.endpoint,
                    response.manifest_hex.len(),
                    MAX_MANIFEST_HEX_LEN
                );
                continue;
            }

            let manifest_bytes = match hex_decode(&response.manifest_hex) {
                Ok(bytes) => bytes,
                Err(err) => {
                    self.record_source_failure(&source.endpoint).await;
                    last_error = format!("{}: invalid manifest hex: {err}", source.endpoint);
                    continue;
                }
            };

            let computed_snapshot_id = hex_encode(snapshot_id_from_manifest(&manifest_bytes));
            if computed_snapshot_id != snapshot_id {
                self.record_source_failure(&source.endpoint).await;
                last_error = format!(
                    "{}: manifest snapshot id mismatch (expected {}, got {})",
                    source.endpoint, snapshot_id, computed_snapshot_id
                );
                continue;
            }
            self.record_source_success(&source.endpoint).await;
            valid_responses += 1;
            let vote_key = hash_chunk_bytes(&manifest_bytes);
            let vote = votes.entry(vote_key).or_insert_with(|| ManifestVote { manifest_bytes: manifest_bytes.clone(), vote_count: 0 });
            vote.vote_count += 1;
        }

        if votes.is_empty() {
            return Err(format!("failed fetching snapshot manifest `{snapshot_id}`: {last_error}"));
        }

        let mut vote_entries = votes.into_iter().collect::<Vec<_>>();
        vote_entries.sort_by(|a, b| b.1.vote_count.cmp(&a.1.vote_count).then_with(|| a.0.cmp(&b.0)));

        let (_vote_hash, winning_vote) = vote_entries.remove(0);
        let vote_count = winning_vote.vote_count;
        if valid_responses < required_votes || vote_count < required_votes {
            return Err(format!(
                "manifest quorum not reached for snapshot `{snapshot_id}` (required votes: {}, responses: {}, winning votes: {})",
                required_votes, valid_responses, vote_count
            ));
        }
        if valid_responses > vote_count {
            warn!(
                "[atomic-bootstrap] manifest conflicts detected for snapshot {} (winning votes: {}/{})",
                snapshot_id, vote_count, valid_responses
            );
        }

        Ok(winning_vote.manifest_bytes)
    }

    fn validate_manifest_sanity(&self, manifest: &SnapshotManifestV2) -> Result<(), String> {
        if manifest.snapshot_file_name.is_empty() {
            return Err("manifest snapshot_file_name cannot be empty".to_string());
        }
        if !is_safe_snapshot_file_name(&manifest.snapshot_file_name) {
            return Err(format!(
                "manifest snapshot_file_name `{}` must be a plain file name without path components",
                manifest.snapshot_file_name
            ));
        }

        if manifest.snapshot_file_size == 0 {
            return Err("manifest snapshot_file_size cannot be zero".to_string());
        }
        if manifest.snapshot_file_size > MAX_SNAPSHOT_FILE_SIZE_BYTES {
            return Err(format!(
                "manifest snapshot_file_size {} exceeds max {}",
                manifest.snapshot_file_size, MAX_SNAPSHOT_FILE_SIZE_BYTES
            ));
        }

        if manifest.replay_window_size > MAX_REPLAY_FILE_SIZE_BYTES {
            return Err(format!(
                "manifest replay_window_size {} exceeds max {}",
                manifest.replay_window_size, MAX_REPLAY_FILE_SIZE_BYTES
            ));
        }

        if manifest.snapshot_chunk_size == 0 || manifest.snapshot_chunk_size > MAX_ALLOWED_CHUNK_SIZE {
            return Err(format!(
                "manifest snapshot_chunk_size {} out of range (1..={})",
                manifest.snapshot_chunk_size, MAX_ALLOWED_CHUNK_SIZE
            ));
        }
        if manifest.replay_window_chunk_size == 0 || manifest.replay_window_chunk_size > MAX_ALLOWED_CHUNK_SIZE {
            return Err(format!(
                "manifest replay_window_chunk_size {} out of range (1..={})",
                manifest.replay_window_chunk_size, MAX_ALLOWED_CHUNK_SIZE
            ));
        }

        let expected_snapshot_chunks = expected_chunk_count(manifest.snapshot_file_size, manifest.snapshot_chunk_size)?;
        if expected_snapshot_chunks == 0 || expected_snapshot_chunks > MAX_TOTAL_CHUNKS {
            return Err(format!(
                "manifest snapshot chunk count {} is out of range (1..={})",
                expected_snapshot_chunks, MAX_TOTAL_CHUNKS
            ));
        }
        if manifest.snapshot_chunk_hashes.len() != expected_snapshot_chunks {
            return Err(format!(
                "manifest snapshot chunk hash count mismatch: expected {}, got {}",
                expected_snapshot_chunks,
                manifest.snapshot_chunk_hashes.len()
            ));
        }

        let expected_replay_chunks = expected_chunk_count(manifest.replay_window_size, manifest.replay_window_chunk_size)?;
        if expected_replay_chunks > MAX_TOTAL_CHUNKS {
            return Err(format!("manifest replay chunk count {} exceeds max {}", expected_replay_chunks, MAX_TOTAL_CHUNKS));
        }
        if manifest.replay_window_chunk_hashes.len() != expected_replay_chunks {
            return Err(format!(
                "manifest replay chunk hash count mismatch: expected {}, got {}",
                expected_replay_chunks,
                manifest.replay_window_chunk_hashes.len()
            ));
        }

        Ok(())
    }

    async fn download_and_verify_snapshot_to_file(
        &self,
        sources: &[SourceClient],
        snapshot_id: &str,
        manifest: &SnapshotManifestV2,
        output_path: &Path,
    ) -> Result<(), String> {
        let expected_total = manifest.snapshot_chunk_hashes.len() as u32;
        if expected_total == 0 {
            return Err("snapshot manifest has zero snapshot chunks".to_string());
        }

        let temp_path = output_path.with_extension("part");
        let mut file = std::fs::File::create(&temp_path)
            .map_err(|err| format!("failed creating snapshot download file `{}`: {err}", temp_path.display()))?;
        let mut snapshot_hasher = Blake2bParams::new().hash_length(32).to_state();
        snapshot_hasher.update(SNAPSHOT_MANIFEST_DOMAIN);
        let mut written = 0u64;
        let mut last_progress_log = Instant::now();
        info!(
            "[atomic-bootstrap] snapshot download started: snapshot={}, chunks={}, bytes={}, chunk_size={}",
            snapshot_id, expected_total, manifest.snapshot_file_size, manifest.snapshot_chunk_size
        );
        for chunk_index in 0..expected_total {
            let response = self
                .fetch_snapshot_chunk_from_sources(
                    sources,
                    snapshot_id,
                    chunk_index,
                    manifest.snapshot_chunk_size,
                    expected_total,
                    manifest.snapshot_file_size,
                )
                .await?;

            let chunk = decode_chunk_payload(
                &response.chunk_hex,
                manifest.snapshot_chunk_size,
                chunk_index,
                expected_total,
                manifest.snapshot_file_size,
                usize::try_from(written).map_err(|_| "snapshot assembled length does not fit usize".to_string())?,
                "snapshot",
            )?;
            verify_expected_chunk_hash(&chunk, &manifest.snapshot_chunk_hashes, chunk_index)?;
            file.write_all(&chunk)
                .map_err(|err| format!("failed writing snapshot chunk {} to `{}`: {err}", chunk_index, temp_path.display()))?;
            snapshot_hasher.update(&chunk);
            written = written.checked_add(chunk.len() as u64).ok_or_else(|| "snapshot assembled size overflow".to_string())?;
            if last_progress_log.elapsed() >= Duration::from_secs(5) || chunk_index + 1 == expected_total {
                info!(
                    "[atomic-bootstrap] snapshot download progress: {}/{} chunk(s), {}/{} bytes",
                    chunk_index + 1,
                    expected_total,
                    written,
                    manifest.snapshot_file_size
                );
                last_progress_log = Instant::now();
            }
        }

        file.sync_all().map_err(|err| format!("failed syncing snapshot download file `{}`: {err}", temp_path.display()))?;

        if written != manifest.snapshot_file_size {
            let _ = std::fs::remove_file(&temp_path);
            return Err(format!("snapshot assembled size mismatch: expected {}, got {}", manifest.snapshot_file_size, written));
        }

        let digest = snapshot_hasher.finalize();
        if digest.as_bytes() != manifest.snapshot_file_hash {
            let _ = std::fs::remove_file(&temp_path);
            return Err("snapshot assembled hash mismatch".to_string());
        }

        if output_path.exists() {
            std::fs::remove_file(output_path)
                .map_err(|err| format!("failed replacing existing snapshot file `{}`: {err}", output_path.display()))?;
        }
        std::fs::rename(&temp_path, output_path)
            .map_err(|err| format!("failed finalizing snapshot download `{}`: {err}", output_path.display()))?;

        info!(
            "[atomic-bootstrap] snapshot download verified: snapshot={}, bytes={}, path={}",
            snapshot_id,
            written,
            output_path.display()
        );
        Ok(())
    }

    async fn download_and_verify_replay_window_to_file(
        &self,
        sources: &[SourceClient],
        snapshot_id: &str,
        manifest: &SnapshotManifestV2,
        output_path: &Path,
    ) -> Result<(), String> {
        let expected_total = manifest.replay_window_chunk_hashes.len() as u32;
        if expected_total == 0 {
            if manifest.replay_window_size != 0 {
                return Err("replay manifest has non-zero size but zero replay chunks".to_string());
            }
            std::fs::write(output_path, [])
                .map_err(|err| format!("failed writing empty replay window `{}`: {err}", output_path.display()))?;
            info!("[atomic-bootstrap] replay window download skipped: snapshot={} has empty replay window", snapshot_id);
            return Ok(());
        }

        let temp_path = output_path.with_extension("part");
        let mut file = std::fs::File::create(&temp_path)
            .map_err(|err| format!("failed creating replay download file `{}`: {err}", temp_path.display()))?;
        let mut replay_hasher = Blake2bParams::new().hash_length(32).to_state();
        replay_hasher.update(SNAPSHOT_MANIFEST_DOMAIN);
        let mut written = 0u64;
        let mut last_progress_log = Instant::now();
        info!(
            "[atomic-bootstrap] replay window download started: snapshot={}, chunks={}, bytes={}, chunk_size={}",
            snapshot_id, expected_total, manifest.replay_window_size, manifest.replay_window_chunk_size
        );
        for chunk_index in 0..expected_total {
            let response = self
                .fetch_replay_window_chunk_from_sources(
                    sources,
                    snapshot_id,
                    chunk_index,
                    manifest.replay_window_chunk_size,
                    expected_total,
                    manifest.replay_window_size,
                )
                .await?;

            let chunk = decode_chunk_payload(
                &response.chunk_hex,
                manifest.replay_window_chunk_size,
                chunk_index,
                expected_total,
                manifest.replay_window_size,
                usize::try_from(written).map_err(|_| "replay assembled length does not fit usize".to_string())?,
                "replay",
            )?;
            verify_expected_chunk_hash(&chunk, &manifest.replay_window_chunk_hashes, chunk_index)?;
            file.write_all(&chunk)
                .map_err(|err| format!("failed writing replay chunk {} to `{}`: {err}", chunk_index, temp_path.display()))?;
            replay_hasher.update(&chunk);
            written = written.checked_add(chunk.len() as u64).ok_or_else(|| "replay assembled size overflow".to_string())?;
            if last_progress_log.elapsed() >= Duration::from_secs(5) || chunk_index + 1 == expected_total {
                info!(
                    "[atomic-bootstrap] replay window download progress: {}/{} chunk(s), {}/{} bytes",
                    chunk_index + 1,
                    expected_total,
                    written,
                    manifest.replay_window_size
                );
                last_progress_log = Instant::now();
            }
        }

        file.sync_all().map_err(|err| format!("failed syncing replay download file `{}`: {err}", temp_path.display()))?;

        if written != manifest.replay_window_size {
            let _ = std::fs::remove_file(&temp_path);
            return Err(format!("replay assembled size mismatch: expected {}, got {}", manifest.replay_window_size, written));
        }

        let digest = replay_hasher.finalize();
        if digest.as_bytes() != manifest.replay_window_hash {
            let _ = std::fs::remove_file(&temp_path);
            return Err("replay assembled hash mismatch".to_string());
        }

        if output_path.exists() {
            std::fs::remove_file(output_path)
                .map_err(|err| format!("failed replacing existing replay file `{}`: {err}", output_path.display()))?;
        }
        std::fs::rename(&temp_path, output_path)
            .map_err(|err| format!("failed finalizing replay download `{}`: {err}", output_path.display()))?;

        info!(
            "[atomic-bootstrap] replay window download verified: snapshot={}, bytes={}, path={}",
            snapshot_id,
            written,
            output_path.display()
        );
        Ok(())
    }

    async fn fetch_snapshot_chunk_from_sources(
        &self,
        sources: &[SourceClient],
        snapshot_id: &str,
        chunk_index: u32,
        chunk_size: u32,
        expected_total_chunks: u32,
        expected_file_size: u64,
    ) -> Result<cryptix_rpc_core::model::message::GetScSnapshotChunkResponse, String> {
        let mut last_error = "chunk unavailable".to_string();

        for offset in 0..sources.len() {
            let source = &sources[(chunk_index as usize + offset) % sources.len()];
            if self.is_source_blocked(&source.endpoint).await {
                continue;
            }

            let request =
                GetScSnapshotChunkRequest { snapshot_id: snapshot_id.to_string(), chunk_index, chunk_size: Some(chunk_size) };

            let response = match timeout(RPC_CALL_TIMEOUT, source.client.get_sc_snapshot_chunk(request)).await {
                Ok(Ok(response)) => response,
                Ok(Err(err)) => {
                    self.record_source_failure(&source.endpoint).await;
                    last_error = format!("{}: {err}", source.endpoint);
                    continue;
                }
                Err(_) => {
                    self.record_source_failure(&source.endpoint).await;
                    last_error = format!("{}: timeout", source.endpoint);
                    continue;
                }
            };

            if response.chunk_index != chunk_index {
                self.record_source_failure(&source.endpoint).await;
                last_error = format!(
                    "{}: snapshot chunk index mismatch (expected {}, got {})",
                    source.endpoint, chunk_index, response.chunk_index
                );
                continue;
            }
            if response.total_chunks != expected_total_chunks {
                self.record_source_failure(&source.endpoint).await;
                last_error = format!(
                    "{}: snapshot total chunk mismatch (expected {}, got {})",
                    source.endpoint, expected_total_chunks, response.total_chunks
                );
                continue;
            }
            if response.file_size != expected_file_size {
                self.record_source_failure(&source.endpoint).await;
                last_error = format!(
                    "{}: snapshot file size mismatch (expected {}, got {})",
                    source.endpoint, expected_file_size, response.file_size
                );
                continue;
            }

            self.record_source_success(&source.endpoint).await;
            return Ok(response);
        }

        Err(format!("failed fetching snapshot chunk {}: {}", chunk_index, last_error))
    }

    async fn fetch_replay_window_chunk_from_sources(
        &self,
        sources: &[SourceClient],
        snapshot_id: &str,
        chunk_index: u32,
        chunk_size: u32,
        expected_total_chunks: u32,
        expected_file_size: u64,
    ) -> Result<cryptix_rpc_core::model::message::GetScReplayWindowChunkResponse, String> {
        let mut last_error = "replay chunk unavailable".to_string();

        for offset in 0..sources.len() {
            let source = &sources[(chunk_index as usize + offset) % sources.len()];
            if self.is_source_blocked(&source.endpoint).await {
                continue;
            }

            let request =
                GetScReplayWindowChunkRequest { snapshot_id: snapshot_id.to_string(), chunk_index, chunk_size: Some(chunk_size) };

            let response = match timeout(RPC_CALL_TIMEOUT, source.client.get_sc_replay_window_chunk(request)).await {
                Ok(Ok(response)) => response,
                Ok(Err(err)) => {
                    self.record_source_failure(&source.endpoint).await;
                    last_error = format!("{}: {err}", source.endpoint);
                    continue;
                }
                Err(_) => {
                    self.record_source_failure(&source.endpoint).await;
                    last_error = format!("{}: timeout", source.endpoint);
                    continue;
                }
            };

            if response.chunk_index != chunk_index {
                self.record_source_failure(&source.endpoint).await;
                last_error = format!(
                    "{}: replay chunk index mismatch (expected {}, got {})",
                    source.endpoint, chunk_index, response.chunk_index
                );
                continue;
            }
            if response.total_chunks != expected_total_chunks {
                self.record_source_failure(&source.endpoint).await;
                last_error = format!(
                    "{}: replay total chunk mismatch (expected {}, got {})",
                    source.endpoint, expected_total_chunks, response.total_chunks
                );
                continue;
            }
            if response.file_size != expected_file_size {
                self.record_source_failure(&source.endpoint).await;
                last_error = format!(
                    "{}: replay file size mismatch (expected {}, got {})",
                    source.endpoint, expected_file_size, response.file_size
                );
                continue;
            }

            self.record_source_success(&source.endpoint).await;
            return Ok(response);
        }

        Err(format!("failed fetching replay chunk {}: {}", chunk_index, last_error))
    }

    async fn is_source_blocked(&self, endpoint: &str) -> bool {
        let mut penalties = self.source_penalties.lock().await;
        let now = Instant::now();
        if let Some(entry) = penalties.get_mut(endpoint) {
            if let Some(until) = entry.blocked_until {
                if now >= until {
                    entry.blocked_until = None;
                    entry.failures = 0;
                    return false;
                }
                return true;
            }
        }
        false
    }

    async fn record_source_success(&self, endpoint: &str) {
        let mut penalties = self.source_penalties.lock().await;
        if let Some(entry) = penalties.get_mut(endpoint) {
            entry.failures = entry.failures.saturating_sub(1);
            if entry.failures == 0 {
                entry.blocked_until = None;
            }
        }
    }

    async fn record_source_failure(&self, endpoint: &str) {
        let mut penalties = self.source_penalties.lock().await;
        let entry = penalties.entry(endpoint.to_string()).or_default();
        entry.failures = entry.failures.saturating_add(1);
        if entry.failures >= SOURCE_FAILURE_THRESHOLD {
            entry.blocked_until = Some(Instant::now() + SOURCE_RETRY_COOLDOWN);
        }
    }
}

#[async_trait]
impl AtomicStateQuorumVerifier for AtomicBootstrapService {
    async fn verify_consensus_atomic_state_hash(&self, block_hash: BlockHash, state_hash: [u8; 32]) -> Result<(), String> {
        self.verify_consensus_atomic_state_hash_quorum(block_hash, state_hash).await
    }

    async fn verify_consensus_atomic_state_hash_at_daa(
        &self,
        block_hash: BlockHash,
        state_hash: [u8; 32],
        anchor_daa_score: u64,
    ) -> Result<(), String> {
        self.verify_consensus_atomic_state_hash_quorum_at_daa(block_hash, state_hash, anchor_daa_score).await
    }

    async fn local_atomic_token_state_hash_for_peer(&self, block_hash: BlockHash) -> Result<Option<[u8; 32]>, String> {
        self.local_consensus_p2p_token_audit_hash(block_hash).await
    }

    async fn repair_atomic_index_once(&self) -> Result<bool, String> {
        self.try_bootstrap_once().await
    }
}

impl AsyncService for AtomicBootstrapService {
    fn ident(self: Arc<Self>) -> &'static str {
        SERVICE_IDENT
    }

    fn start(self: Arc<Self>) -> AsyncServiceFuture {
        trace!("{} starting", SERVICE_IDENT);
        let shutdown_signal = self.shutdown.listener.clone();
        Box::pin(async move {
            let mut ticker = interval(self.retry_interval);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = shutdown_signal.clone() => break,
                    _ = ticker.tick() => {
                        match self.try_bootstrap_once().await {
                            Ok(true) => {
                                info!("[atomic-bootstrap] Atomic bootstrap/repair completed successfully");
                            }
                            Ok(false) => {}
                            Err(err) => {
                                warn!("[atomic-bootstrap] bootstrap attempt failed: {err}");
                            }
                        }
                    }
                }
            }
            Ok(())
        })
    }

    fn signal_exit(self: Arc<Self>) {
        self.shutdown.trigger.trigger();
    }

    fn stop(self: Arc<Self>) -> AsyncServiceFuture {
        Box::pin(async move { Ok(()) })
    }
}

fn merge_source_kind(existing: SourceKind, incoming: SourceKind) -> SourceKind {
    if matches!(existing, SourceKind::Seed) || matches!(incoming, SourceKind::Seed) {
        SourceKind::Seed
    } else if matches!(existing, SourceKind::Configured) || matches!(incoming, SourceKind::Configured) {
        SourceKind::Configured
    } else {
        SourceKind::Peer
    }
}

fn health_audit_initial_delay(interval: Duration, atomic_data_dir: &Path) -> Duration {
    let max_jitter_secs = interval.as_secs().min(60);
    if max_jitter_secs == 0 {
        return Duration::ZERO;
    }

    let mut hasher = DefaultHasher::new();
    atomic_data_dir.hash(&mut hasher);
    std::process::id().hash(&mut hasher);
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos().hash(&mut hasher);
    Duration::from_secs(hasher.finish() % max_jitter_secs)
}

fn p2p_audit_sample_score(block_hash: BlockHash, source_identity: &str) -> [u8; 32] {
    let mut hasher = Blake2bParams::new().hash_length(32).to_state();
    hasher.update(b"CRYPTIX_ATOMIC_P2P_AUDIT_SAMPLE_V1");
    hasher.update(&block_hash.as_bytes());
    hasher.update(source_identity.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_bytes());
    out
}

fn push_candidate_endpoint(
    endpoints: &mut Vec<CandidateEndpoint>,
    by_endpoint: &mut HashMap<String, usize>,
    endpoint: String,
    expected_node_identity: Option<[u8; 32]>,
    kind: SourceKind,
) {
    if let Some(existing_idx) = by_endpoint.get(&endpoint).copied() {
        let existing = &mut endpoints[existing_idx];
        existing.kind = merge_source_kind(existing.kind, kind);
        if existing.expected_node_identity.is_none() {
            existing.expected_node_identity = expected_node_identity;
        }
        return;
    }

    let idx = endpoints.len();
    endpoints.push(CandidateEndpoint { endpoint: endpoint.clone(), expected_node_identity, kind });
    by_endpoint.insert(endpoint, idx);
}

fn source_preferred_over(candidate: &SourceClient, current: &SourceClient) -> bool {
    (candidate.head.at_daa_score, candidate.head.at_block_hash.to_string())
        > (current.head.at_daa_score, current.head.at_block_hash.to_string())
}

fn snapshot_evidence_summary(evidence: &[SnapshotSupportEvidence]) -> String {
    if evidence.is_empty() {
        return "[]".to_string();
    }

    let mut rows = evidence
        .iter()
        .map(|source| {
            format!(
                "{{label={}, identity={}, kind={:?}, hash={}, daa={}, block={}}}",
                source.source_label,
                source.source_identity,
                source.kind,
                source.snapshot_id,
                source.at_daa_score,
                source.at_block_hash
            )
        })
        .collect::<Vec<_>>();
    rows.sort_unstable();
    format!("[{}]", rows.join(", "))
}

fn snapshot_quorum_policy_for_network(
    is_mainnet: bool,
    _disable_dns_seed_sources: bool,
    allow_peer_majority_fallback_override: bool,
    seed_confirmed_min_non_seed_sources: usize,
    peer_majority_min_sources: usize,
) -> SnapshotQuorumPolicy {
    let seed_confirmed_min_non_seed_sources = seed_confirmed_min_non_seed_sources.max(1);
    let peer_majority_min_sources = peer_majority_min_sources.max(1);
    if is_mainnet {
        SnapshotQuorumPolicy {
            allow_peer_majority_fallback: allow_peer_majority_fallback_override,
            require_seed_confirmed_if_any_seed: true,
            seed_confirmed_min_non_seed_sources,
            peer_majority_min_sources,
        }
    } else {
        SnapshotQuorumPolicy {
            allow_peer_majority_fallback: true,
            require_seed_confirmed_if_any_seed: false,
            seed_confirmed_min_non_seed_sources,
            peer_majority_min_sources,
        }
    }
}

fn select_snapshot_quorum(
    evidence: Vec<SnapshotSupportEvidence>,
    allow_peer_majority_fallback: bool,
    require_seed_confirmed_if_any_seed: bool,
    seed_confirmed_min_non_seed_sources: usize,
    peer_majority_min_sources: usize,
) -> Result<SnapshotQuorumDecision, String> {
    let evidence_summary = snapshot_evidence_summary(&evidence);

    #[derive(Clone, Debug)]
    struct SnapshotCandidate {
        snapshot_id: String,
        support: usize,
        seed_support: usize,
        non_seed_support: usize,
        best_daa: u64,
        best_block_hash: String,
    }

    let mut unique_identities = HashMap::<String, SourceKind>::new();
    let mut unique_support = HashMap::<(String, String), SnapshotSupportEvidence>::new();
    for mut source in evidence {
        let snapshot_id = source.snapshot_id.to_ascii_lowercase();
        source.snapshot_id = snapshot_id.clone();
        unique_identities
            .entry(source.source_identity.clone())
            .and_modify(|kind| *kind = merge_source_kind(*kind, source.kind))
            .or_insert(source.kind);

        let support_key = (source.source_identity.clone(), snapshot_id);
        if let Some(existing) = unique_support.get_mut(&support_key) {
            let merged_kind = merge_source_kind(existing.kind, source.kind);
            let replace_existing =
                (source.at_daa_score, source.at_block_hash.clone()) > (existing.at_daa_score, existing.at_block_hash.clone());
            if replace_existing {
                source.kind = merged_kind;
                *existing = source;
            } else {
                existing.kind = merged_kind;
            }
            continue;
        }

        unique_support.insert(support_key, source);
    }

    let mut grouped: HashMap<String, Vec<SnapshotSupportEvidence>> = HashMap::new();
    for source in unique_support.into_values() {
        grouped.entry(source.snapshot_id.clone()).or_default().push(source);
    }

    let total_seed_sources = unique_identities.values().filter(|kind| matches!(kind, SourceKind::Seed)).count();
    let total_non_seed_sources = unique_identities.len().saturating_sub(total_seed_sources);
    let mut candidates = grouped
        .into_iter()
        .map(|(snapshot_id, group_sources)| {
            let support = group_sources.len();
            let seed_support = group_sources.iter().filter(|s| matches!(s.kind, SourceKind::Seed)).count();
            let non_seed_support = support.saturating_sub(seed_support);
            let best_daa = group_sources.iter().map(|s| s.at_daa_score).max().unwrap_or(0);
            let best_block_hash = group_sources.iter().map(|s| s.at_block_hash.clone()).max().unwrap_or_default();

            SnapshotCandidate { snapshot_id, support, seed_support, non_seed_support, best_daa, best_block_hash }
        })
        .collect::<Vec<_>>();

    if candidates.is_empty() {
        return Err(format!("no snapshot candidates available after grouping; evidence={evidence_summary}"));
    }

    candidates.sort_by(|a, b| {
        b.support
            .cmp(&a.support)
            .then(b.seed_support.cmp(&a.seed_support))
            .then(b.non_seed_support.cmp(&a.non_seed_support))
            .then(b.best_daa.cmp(&a.best_daa))
            .then(b.best_block_hash.cmp(&a.best_block_hash))
    });

    let mut seed_quorum_failure: Option<String> = None;

    let seed_confirmed_min_non_seed_sources = seed_confirmed_min_non_seed_sources.max(1);
    if total_seed_sources > 0 {
        if let Some(selected) = candidates.iter().find(|candidate| {
            candidate.seed_support >= ATOMIC_BOOTSTRAP_REQUIRED_SEED_SOURCES
                && candidate.non_seed_support >= seed_confirmed_min_non_seed_sources
        }) {
            let required_votes = ATOMIC_BOOTSTRAP_REQUIRED_SEED_SOURCES + seed_confirmed_min_non_seed_sources;
            return Ok(SnapshotQuorumDecision {
                snapshot_id: selected.snapshot_id.clone(),
                required_votes,
                policy_description: format!(
                    "seed-confirmed quorum (required: >={ATOMIC_BOOTSTRAP_REQUIRED_SEED_SOURCES} seed + >={seed_confirmed_min_non_seed_sources} independent non-seeds; seed support: {}, non-seed support: {}, total support: {})",
                    selected.seed_support,
                    selected.non_seed_support,
                    selected.support
                ),
            });
        }

        seed_quorum_failure = Some(format!(
            "seed-confirmed bootstrap quorum not reached: found {total_seed_sources} reachable seed source(s) but no snapshot matched by >={ATOMIC_BOOTSTRAP_REQUIRED_SEED_SOURCES} seed plus >={seed_confirmed_min_non_seed_sources} independent non-seed sources"
        ));
    }

    if require_seed_confirmed_if_any_seed {
        if let Some(seed_err) = seed_quorum_failure.clone() {
            return Err(seed_err);
        }
    }

    if !allow_peer_majority_fallback {
        return Err(seed_quorum_failure.unwrap_or_else(|| {
            "peer-majority bootstrap disabled by policy: fallback is disabled while no seed source is reachable".to_string()
        }));
    }

    let peer_majority_min_sources = peer_majority_min_sources.max(1);
    if total_non_seed_sources < peer_majority_min_sources {
        let fallback_err = format!(
            "peer-majority bootstrap unavailable: only {total_non_seed_sources} independent non-seed source(s) available (minimum required: {peer_majority_min_sources}); evidence={evidence_summary}"
        );
        return Err(match seed_quorum_failure {
            Some(seed_err) => format!("{seed_err}; {fallback_err}"),
            None => fallback_err,
        });
    }

    let majority_votes = (total_non_seed_sources / 2) + 1;
    let required_votes = majority_votes.max(peer_majority_min_sources);
    let selected = candidates
        .iter()
        .max_by(|a, b| {
            a.non_seed_support
                .cmp(&b.non_seed_support)
                .then(a.support.cmp(&b.support))
                .then(a.best_daa.cmp(&b.best_daa))
                .then(a.best_block_hash.cmp(&b.best_block_hash))
                .then(a.snapshot_id.cmp(&b.snapshot_id))
        })
        .ok_or_else(|| "peer-majority bootstrap unavailable: no snapshot candidates after non-seed grouping".to_string())?;
    if selected.non_seed_support < required_votes {
        let fallback_err = format!(
            "peer-majority bootstrap quorum not reached for `{}` (required votes: {required_votes}, matching non-seed sources: {}, total non-seed sources: {total_non_seed_sources}); evidence={evidence_summary}",
            selected.snapshot_id, selected.non_seed_support
        );
        return Err(match seed_quorum_failure {
            Some(seed_err) => format!("{seed_err}; {fallback_err}"),
            None => fallback_err,
        });
    }

    let fallback_reason = if seed_quorum_failure.is_some() {
        "seed-fallback peer-majority quorum (seed sources reachable but unusable)"
    } else {
        "peer-majority quorum (no reachable seed source)"
    };

    Ok(SnapshotQuorumDecision {
        snapshot_id: selected.snapshot_id.clone(),
        required_votes,
        policy_description: format!(
            "{fallback_reason} (minimum independent non-seed sources: {peer_majority_min_sources}, matching non-seed sources: {}/{total_non_seed_sources}, total support: {})",
            selected.non_seed_support, selected.support
        ),
    })
}

fn expected_chunk_count(file_size: u64, chunk_size: u32) -> Result<usize, String> {
    if chunk_size == 0 {
        return Err("chunk_size cannot be zero".to_string());
    }
    if file_size == 0 {
        return Ok(0);
    }

    let chunk_size = chunk_size as u64;
    let total = file_size.checked_add(chunk_size - 1).ok_or_else(|| "chunk count overflow while validating manifest".to_string())?
        / chunk_size;
    usize::try_from(total).map_err(|_| "chunk count does not fit in usize".to_string())
}

fn is_safe_snapshot_file_name(file_name: &str) -> bool {
    let path = Path::new(file_name);
    path.components().count() == 1 && path.file_name().and_then(|name| name.to_str()) == Some(file_name)
}

fn decode_chunk_payload(
    chunk_hex: &str,
    declared_chunk_size: u32,
    chunk_index: u32,
    total_chunks: u32,
    file_size: u64,
    assembled_len: usize,
    scope: &str,
) -> Result<Vec<u8>, String> {
    let max_hex_len =
        usize::try_from(declared_chunk_size).map_err(|_| format!("{scope} chunk size does not fit usize"))?.saturating_mul(2);
    if chunk_hex.len() > max_hex_len {
        return Err(format!("{scope} chunk {} hex length {} exceeds max {}", chunk_index, chunk_hex.len(), max_hex_len));
    }

    let chunk = hex_decode(chunk_hex).map_err(|err| format!("{scope} chunk {chunk_index} has invalid hex payload: {err}"))?;

    let expected_file_size =
        usize::try_from(file_size).map_err(|_| format!("{scope} file size {file_size} does not fit in usize on this platform"))?;
    if assembled_len > expected_file_size {
        return Err(format!("{scope} assembled length {} already exceeds declared file size {}", assembled_len, expected_file_size));
    }

    let remaining = expected_file_size.saturating_sub(assembled_len);
    if chunk.len() > remaining {
        return Err(format!("{scope} chunk {} size {} exceeds remaining file size {}", chunk_index, chunk.len(), remaining));
    }
    if chunk.is_empty() && remaining > 0 {
        return Err(format!("{scope} chunk {} is empty while {} bytes remain", chunk_index, remaining));
    }

    let declared_chunk_size = declared_chunk_size as usize;
    let is_last_chunk = chunk_index + 1 == total_chunks;
    if !is_last_chunk && chunk.len() != declared_chunk_size {
        return Err(format!(
            "{scope} chunk {} invalid size: expected exactly {}, got {}",
            chunk_index,
            declared_chunk_size,
            chunk.len()
        ));
    }

    Ok(chunk)
}

fn hash_chunk_bytes(bytes: &[u8]) -> [u8; 32] {
    let digest = Blake2bParams::new().hash_length(32).hash(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_bytes());
    out
}

fn verify_expected_chunk_hash(chunk_data: &[u8], expected_hashes: &[[u8; 32]], chunk_index: u32) -> Result<(), String> {
    let expected =
        expected_hashes.get(chunk_index as usize).ok_or_else(|| format!("missing expected hash for chunk {}", chunk_index))?;
    let actual = hash_chunk_bytes(chunk_data);
    if &actual != expected {
        return Err(format!("chunk hash mismatch at index {}", chunk_index));
    }
    Ok(())
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

fn decode_hash32_hex(value: &str) -> Result<[u8; 32], String> {
    let decoded = hex_decode(value).map_err(|err| format!("invalid hex `{value}`: {err}"))?;
    if decoded.len() != 32 {
        return Err(format!("invalid hash length for `{value}`: expected 32 bytes, got {}", decoded.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{
        select_snapshot_quorum, snapshot_quorum_policy_for_network, SnapshotSupportEvidence, SourceKind,
        ATOMIC_BOOTSTRAP_DEFAULT_PEER_MAJORITY_MIN_SOURCES, ATOMIC_BOOTSTRAP_DEFAULT_SEED_CONFIRMED_NON_SEED_SOURCES,
        ATOMIC_BOOTSTRAP_REQUIRED_SEED_SOURCES, ATOMIC_BOOTSTRAP_REQUIRED_TOTAL_SOURCES,
    };

    fn evidence(
        source_identity: &str,
        snapshot_id: &str,
        kind: SourceKind,
        at_daa_score: u64,
        at_block_hash: &str,
    ) -> SnapshotSupportEvidence {
        SnapshotSupportEvidence {
            source_identity: source_identity.to_string(),
            source_label: source_identity.to_string(),
            snapshot_id: snapshot_id.to_string(),
            kind,
            at_daa_score,
            at_block_hash: at_block_hash.to_string(),
        }
    }

    #[test]
    fn quorum_policy_seed_plus_peer_accepts_match() {
        let decision = select_snapshot_quorum(
            vec![
                evidence("seed-1", "snapshot-a", SourceKind::Seed, 120, "aaaa"),
                evidence("peer-1", "snapshot-a", SourceKind::Peer, 120, "aaaa"),
                evidence("peer-2", "snapshot-a", SourceKind::Peer, 119, "aaaa"),
                evidence("peer-3", "snapshot-b", SourceKind::Peer, 118, "bbbb"),
            ],
            true,
            true,
            ATOMIC_BOOTSTRAP_DEFAULT_SEED_CONFIRMED_NON_SEED_SOURCES,
            ATOMIC_BOOTSTRAP_DEFAULT_PEER_MAJORITY_MIN_SOURCES,
        )
        .expect("seed + two additional sources should satisfy quorum");

        assert_eq!(decision.snapshot_id, "snapshot-a");
        assert_eq!(decision.required_votes, ATOMIC_BOOTSTRAP_REQUIRED_TOTAL_SOURCES);
        assert!(decision.policy_description.contains("seed-confirmed quorum"));
        assert!(decision.policy_description.contains(&format!(
            ">={ATOMIC_BOOTSTRAP_REQUIRED_SEED_SOURCES} seed + >={ATOMIC_BOOTSTRAP_DEFAULT_SEED_CONFIRMED_NON_SEED_SOURCES} independent non-seeds"
        )));
    }

    #[test]
    fn quorum_policy_accepts_common_older_snapshot_when_heads_are_skewed() {
        let decision = select_snapshot_quorum(
            vec![
                evidence("seed-1", "snapshot-seed-head", SourceKind::Seed, 130, "seed-head"),
                evidence("seed-1", "snapshot-common", SourceKind::Seed, 120, "common"),
                evidence("peer-1", "snapshot-peer-1-head", SourceKind::Peer, 132, "peer-1-head"),
                evidence("peer-1", "snapshot-common", SourceKind::Peer, 120, "common"),
                evidence("peer-2", "snapshot-peer-2-head", SourceKind::Peer, 131, "peer-2-head"),
                evidence("peer-2", "snapshot-common", SourceKind::Peer, 120, "common"),
            ],
            true,
            true,
            ATOMIC_BOOTSTRAP_DEFAULT_SEED_CONFIRMED_NON_SEED_SOURCES,
            ATOMIC_BOOTSTRAP_DEFAULT_PEER_MAJORITY_MIN_SOURCES,
        )
        .expect("seed and peers should quorum on a common retained snapshot even when their latest heads differ");

        assert_eq!(decision.snapshot_id, "snapshot-common");
        assert_eq!(decision.required_votes, ATOMIC_BOOTSTRAP_REQUIRED_TOTAL_SOURCES);
        assert!(decision.policy_description.contains("seed-confirmed quorum"));
    }

    #[test]
    fn quorum_policy_seed_plus_one_non_seed_rejects_match() {
        let err = select_snapshot_quorum(
            vec![
                evidence("seed-1", "snapshot-a", SourceKind::Seed, 120, "aaaa"),
                evidence("peer-1", "snapshot-a", SourceKind::Peer, 120, "aaaa"),
                evidence("peer-2", "snapshot-b", SourceKind::Peer, 119, "bbbb"),
            ],
            true,
            true,
            ATOMIC_BOOTSTRAP_DEFAULT_SEED_CONFIRMED_NON_SEED_SOURCES,
            ATOMIC_BOOTSTRAP_DEFAULT_PEER_MAJORITY_MIN_SOURCES,
        )
        .expect_err("seed + one non-seed must not satisfy seed-confirmed quorum");

        assert!(err.contains("seed-confirmed bootstrap quorum not reached"), "unexpected error message: {err}");
    }

    #[test]
    fn quorum_policy_seed_plus_one_non_seed_accepts_explicit_override() {
        let decision = select_snapshot_quorum(
            vec![
                evidence("seed-1", "snapshot-a", SourceKind::Seed, 120, "aaaa"),
                evidence("peer-1", "snapshot-a", SourceKind::Peer, 120, "aaaa"),
            ],
            true,
            true,
            1,
            ATOMIC_BOOTSTRAP_DEFAULT_PEER_MAJORITY_MIN_SOURCES,
        )
        .expect("operator override should allow seed + one independent non-seed for private bootstrap testing");

        assert_eq!(decision.snapshot_id, "snapshot-a");
        assert_eq!(decision.required_votes, 2);
        assert!(decision.policy_description.contains(">=1 independent non-seeds"));
    }

    #[test]
    fn quorum_policy_peer_majority_without_seed_accepts_match() {
        let decision = select_snapshot_quorum(
            vec![
                evidence("peer-1", "snapshot-x", SourceKind::Peer, 220, "xxxx"),
                evidence("peer-2", "snapshot-x", SourceKind::Configured, 220, "xxxx"),
                evidence("peer-3", "snapshot-x", SourceKind::Peer, 219, "xxxx"),
                evidence("peer-4", "snapshot-y", SourceKind::Configured, 218, "yyyy"),
            ],
            true,
            true,
            ATOMIC_BOOTSTRAP_DEFAULT_SEED_CONFIRMED_NON_SEED_SOURCES,
            ATOMIC_BOOTSTRAP_DEFAULT_PEER_MAJORITY_MIN_SOURCES,
        )
        .expect("3 of 4 non-seed sources should satisfy peer-majority quorum");

        assert_eq!(decision.snapshot_id, "snapshot-x");
        assert_eq!(decision.required_votes, ATOMIC_BOOTSTRAP_REQUIRED_TOTAL_SOURCES);
        assert!(decision.policy_description.contains("peer-majority quorum"));
    }

    #[test]
    fn quorum_policy_seed_unusable_can_fallback_to_peer_majority_on_non_strict_policy() {
        let decision = select_snapshot_quorum(
            vec![
                evidence("seed-1", "snapshot-a", SourceKind::Seed, 220, "aaaa"),
                evidence("seed-2", "snapshot-b", SourceKind::Seed, 220, "bbbb"),
                evidence("peer-1", "snapshot-x", SourceKind::Peer, 220, "xxxx"),
                evidence("peer-2", "snapshot-x", SourceKind::Configured, 220, "xxxx"),
                evidence("peer-3", "snapshot-x", SourceKind::Peer, 219, "xxxx"),
                evidence("peer-4", "snapshot-y", SourceKind::Configured, 218, "yyyy"),
            ],
            true,
            false,
            ATOMIC_BOOTSTRAP_DEFAULT_SEED_CONFIRMED_NON_SEED_SOURCES,
            ATOMIC_BOOTSTRAP_DEFAULT_PEER_MAJORITY_MIN_SOURCES,
        )
        .expect("when seed-confirmed quorum is unavailable, peer-majority fallback should still work");

        assert_eq!(decision.snapshot_id, "snapshot-x");
        assert_eq!(decision.required_votes, ATOMIC_BOOTSTRAP_REQUIRED_TOTAL_SOURCES);
        assert!(decision.policy_description.contains("seed-fallback peer-majority quorum"));
    }

    #[test]
    fn quorum_policy_seed_unusable_is_rejected_on_strict_policy() {
        let err = select_snapshot_quorum(
            vec![
                evidence("seed-1", "snapshot-a", SourceKind::Seed, 220, "aaaa"),
                evidence("seed-2", "snapshot-b", SourceKind::Seed, 220, "bbbb"),
                evidence("peer-1", "snapshot-x", SourceKind::Peer, 220, "xxxx"),
                evidence("peer-2", "snapshot-x", SourceKind::Configured, 220, "xxxx"),
                evidence("peer-3", "snapshot-x", SourceKind::Peer, 219, "xxxx"),
                evidence("peer-4", "snapshot-y", SourceKind::Configured, 218, "yyyy"),
            ],
            true,
            true,
            ATOMIC_BOOTSTRAP_DEFAULT_SEED_CONFIRMED_NON_SEED_SOURCES,
            ATOMIC_BOOTSTRAP_DEFAULT_PEER_MAJORITY_MIN_SOURCES,
        )
        .expect_err("strict seed policy must not fallback to peer-majority while any seed is reachable");

        assert!(err.contains("seed-confirmed bootstrap quorum not reached"), "unexpected error message: {err}");
    }

    #[test]
    fn quorum_policy_without_seed_requires_minimum_three_non_seed_sources() {
        let err = select_snapshot_quorum(
            vec![
                evidence("peer-1", "snapshot-x", SourceKind::Peer, 220, "xxxx"),
                evidence("peer-2", "snapshot-x", SourceKind::Configured, 220, "xxxx"),
            ],
            true,
            true,
            ATOMIC_BOOTSTRAP_DEFAULT_SEED_CONFIRMED_NON_SEED_SOURCES,
            ATOMIC_BOOTSTRAP_DEFAULT_PEER_MAJORITY_MIN_SOURCES,
        )
        .expect_err("without seed, fewer than three non-seed sources must fail");

        assert!(
            err.contains(&format!("minimum required: {ATOMIC_BOOTSTRAP_REQUIRED_TOTAL_SOURCES}")),
            "unexpected error message: {err}"
        );
    }

    #[test]
    fn quorum_policy_peer_majority_without_seed_requires_configured_matching_sources() {
        let err = select_snapshot_quorum(
            vec![
                evidence("peer-1", "snapshot-x", SourceKind::Peer, 220, "xxxx"),
                evidence("peer-2", "snapshot-x", SourceKind::Configured, 220, "xxxx"),
                evidence("peer-3", "snapshot-y", SourceKind::Peer, 219, "yyyy"),
            ],
            true,
            true,
            ATOMIC_BOOTSTRAP_DEFAULT_SEED_CONFIRMED_NON_SEED_SOURCES,
            ATOMIC_BOOTSTRAP_DEFAULT_PEER_MAJORITY_MIN_SOURCES,
        )
        .expect_err("2 of 3 non-seed sources must not satisfy a 3-source peer quorum");

        assert!(err.contains("required votes: 3"), "unexpected error message: {err}");
    }

    #[test]
    fn quorum_policy_peer_majority_without_seed_accepts_three_matching_sources() {
        let decision = select_snapshot_quorum(
            vec![
                evidence("peer-1", "snapshot-x", SourceKind::Peer, 220, "xxxx"),
                evidence("peer-2", "snapshot-x", SourceKind::Configured, 220, "xxxx"),
                evidence("peer-3", "snapshot-x", SourceKind::Peer, 219, "xxxx"),
            ],
            true,
            true,
            ATOMIC_BOOTSTRAP_DEFAULT_SEED_CONFIRMED_NON_SEED_SOURCES,
            ATOMIC_BOOTSTRAP_DEFAULT_PEER_MAJORITY_MIN_SOURCES,
        )
        .expect("3 matching non-seed sources should satisfy a 3-source peer quorum");

        assert_eq!(decision.snapshot_id, "snapshot-x");
        assert_eq!(decision.required_votes, ATOMIC_BOOTSTRAP_DEFAULT_PEER_MAJORITY_MIN_SOURCES);
        assert!(decision.policy_description.contains("peer-majority quorum"));
    }

    #[test]
    fn quorum_policy_peer_majority_min_sources_override_accepts_single_source() {
        let decision =
            select_snapshot_quorum(vec![evidence("peer-1", "snapshot-x", SourceKind::Configured, 220, "xxxx")], true, true, 1, 1)
                .expect("explicit single-source peer quorum should allow private bootstrap testing");

        assert_eq!(decision.snapshot_id, "snapshot-x");
        assert_eq!(decision.required_votes, 1);
        assert!(decision.policy_description.contains("minimum independent non-seed sources: 1"));
    }

    #[test]
    fn quorum_policy_no_quorum_returns_error_for_retry_path() {
        let err = select_snapshot_quorum(
            vec![
                evidence("peer-1", "snapshot-l", SourceKind::Peer, 300, "llll"),
                evidence("peer-2", "snapshot-l", SourceKind::Configured, 300, "llll"),
                evidence("peer-3", "snapshot-r", SourceKind::Peer, 300, "rrrr"),
                evidence("peer-4", "snapshot-r", SourceKind::Configured, 300, "rrrr"),
            ],
            true,
            true,
            ATOMIC_BOOTSTRAP_DEFAULT_SEED_CONFIRMED_NON_SEED_SOURCES,
            ATOMIC_BOOTSTRAP_DEFAULT_PEER_MAJORITY_MIN_SOURCES,
        )
        .expect_err("2 vs 2 split must fail majority quorum");

        assert!(err.contains("peer-majority bootstrap quorum not reached"), "unexpected error message: {err}");
    }

    #[test]
    fn quorum_policy_dedupes_same_source_identity_for_seed_plus_peer() {
        let err = select_snapshot_quorum(
            vec![
                evidence("node-a", "snapshot-a", SourceKind::Seed, 500, "aaaa"),
                evidence("node-a", "snapshot-a", SourceKind::Peer, 500, "aaaa"),
                evidence("node-b", "snapshot-a", SourceKind::Peer, 499, "aaaa"),
                evidence("node-c", "snapshot-b", SourceKind::Peer, 498, "bbbb"),
            ],
            true,
            true,
            ATOMIC_BOOTSTRAP_DEFAULT_SEED_CONFIRMED_NON_SEED_SOURCES,
            ATOMIC_BOOTSTRAP_DEFAULT_PEER_MAJORITY_MIN_SOURCES,
        )
        .expect_err("seed and peer views from the same identity must not count as two independent additional votes");

        assert!(err.contains("seed-confirmed bootstrap quorum not reached"), "unexpected error message: {err}");
    }

    #[test]
    fn quorum_policy_dedupes_same_source_identity_for_peer_majority() {
        let err = select_snapshot_quorum(
            vec![
                evidence("node-a", "snapshot-x", SourceKind::Peer, 500, "xxxx"),
                evidence("node-a", "snapshot-x", SourceKind::Configured, 500, "xxxx"),
                evidence("node-b", "snapshot-x", SourceKind::Peer, 499, "xxxx"),
                evidence("node-c", "snapshot-y", SourceKind::Peer, 498, "yyyy"),
                evidence("node-d", "snapshot-y", SourceKind::Configured, 497, "yyyy"),
            ],
            true,
            true,
            ATOMIC_BOOTSTRAP_DEFAULT_SEED_CONFIRMED_NON_SEED_SOURCES,
            ATOMIC_BOOTSTRAP_DEFAULT_PEER_MAJORITY_MIN_SOURCES,
        )
        .expect_err("duplicate identities must not inflate non-seed majority quorum");

        assert!(err.contains("peer-majority bootstrap quorum not reached"), "unexpected error message: {err}");
    }

    #[test]
    fn quorum_policy_without_seed_can_be_disabled() {
        let err = select_snapshot_quorum(
            vec![
                evidence("peer-1", "snapshot-x", SourceKind::Peer, 220, "xxxx"),
                evidence("peer-2", "snapshot-x", SourceKind::Configured, 220, "xxxx"),
                evidence("peer-3", "snapshot-x", SourceKind::Peer, 219, "xxxx"),
                evidence("peer-4", "snapshot-y", SourceKind::Configured, 218, "yyyy"),
            ],
            false,
            true,
            ATOMIC_BOOTSTRAP_DEFAULT_SEED_CONFIRMED_NON_SEED_SOURCES,
            ATOMIC_BOOTSTRAP_DEFAULT_PEER_MAJORITY_MIN_SOURCES,
        )
        .expect_err("peer-majority fallback should be rejected when disabled by policy");

        assert!(err.contains("peer-majority bootstrap disabled by policy"), "unexpected error message: {err}");
    }

    #[test]
    fn network_policy_mainnet_defaults_to_strict_seed_mode() {
        let policy = snapshot_quorum_policy_for_network(
            true,
            false,
            false,
            ATOMIC_BOOTSTRAP_DEFAULT_SEED_CONFIRMED_NON_SEED_SOURCES,
            ATOMIC_BOOTSTRAP_DEFAULT_PEER_MAJORITY_MIN_SOURCES,
        );

        assert!(!policy.allow_peer_majority_fallback);
        assert!(policy.require_seed_confirmed_if_any_seed);
        assert_eq!(policy.seed_confirmed_min_non_seed_sources, ATOMIC_BOOTSTRAP_DEFAULT_SEED_CONFIRMED_NON_SEED_SOURCES);
        assert_eq!(policy.peer_majority_min_sources, ATOMIC_BOOTSTRAP_DEFAULT_PEER_MAJORITY_MIN_SOURCES);
    }

    #[test]
    fn network_policy_mainnet_nodnsseed_keeps_peer_majority_disabled_by_default() {
        let policy = snapshot_quorum_policy_for_network(
            true,
            true,
            false,
            ATOMIC_BOOTSTRAP_DEFAULT_SEED_CONFIRMED_NON_SEED_SOURCES,
            ATOMIC_BOOTSTRAP_DEFAULT_PEER_MAJORITY_MIN_SOURCES,
        );

        assert!(!policy.allow_peer_majority_fallback);
        assert!(policy.require_seed_confirmed_if_any_seed);
        assert_eq!(policy.seed_confirmed_min_non_seed_sources, ATOMIC_BOOTSTRAP_DEFAULT_SEED_CONFIRMED_NON_SEED_SOURCES);
        assert_eq!(policy.peer_majority_min_sources, ATOMIC_BOOTSTRAP_DEFAULT_PEER_MAJORITY_MIN_SOURCES);
    }

    #[test]
    fn network_policy_mainnet_peer_fallback_requires_explicit_override() {
        let policy = snapshot_quorum_policy_for_network(
            true,
            true,
            true,
            ATOMIC_BOOTSTRAP_DEFAULT_SEED_CONFIRMED_NON_SEED_SOURCES,
            ATOMIC_BOOTSTRAP_DEFAULT_PEER_MAJORITY_MIN_SOURCES,
        );

        assert!(policy.allow_peer_majority_fallback);
        assert!(policy.require_seed_confirmed_if_any_seed);
        assert_eq!(policy.seed_confirmed_min_non_seed_sources, ATOMIC_BOOTSTRAP_DEFAULT_SEED_CONFIRMED_NON_SEED_SOURCES);
        assert_eq!(policy.peer_majority_min_sources, ATOMIC_BOOTSTRAP_DEFAULT_PEER_MAJORITY_MIN_SOURCES);
    }

    #[test]
    fn network_policy_non_mainnet_allows_peer_majority_mode() {
        let policy = snapshot_quorum_policy_for_network(
            false,
            false,
            false,
            ATOMIC_BOOTSTRAP_DEFAULT_SEED_CONFIRMED_NON_SEED_SOURCES,
            ATOMIC_BOOTSTRAP_DEFAULT_PEER_MAJORITY_MIN_SOURCES,
        );

        assert!(policy.allow_peer_majority_fallback);
        assert!(!policy.require_seed_confirmed_if_any_seed);
        assert_eq!(policy.seed_confirmed_min_non_seed_sources, ATOMIC_BOOTSTRAP_DEFAULT_SEED_CONFIRMED_NON_SEED_SOURCES);
        assert_eq!(policy.peer_majority_min_sources, ATOMIC_BOOTSTRAP_DEFAULT_PEER_MAJORITY_MIN_SOURCES);
    }
}
