use async_trait::async_trait;
use blake2b_simd::Params as Blake2bParams;
use borsh::BorshDeserialize;
use cryptix_atomicindex::{
    service::{AtomicTokenService, MAX_BOOTSTRAP_REPLAY_WINDOW_SIZE_BYTES, MAX_BOOTSTRAP_SNAPSHOT_FILE_SIZE_BYTES},
    state::AtomicTokenRuntimeState,
};
use cryptix_consensus_core::Hash as BlockHash;
use cryptix_core::{
    info,
    task::service::{AsyncService, AsyncServiceFuture},
    trace, warn,
};
use cryptix_grpc_client::GrpcClient;
use cryptix_p2p_flows::flow_context::{AtomicStateQuorumVerifier, FlowContext};
use cryptix_rpc_core::{
    api::rpc::RpcApi,
    model::message::{
        GetConsensusAtomicStateHashRequest, GetScReplayWindowChunkRequest, GetScSnapshotChunkRequest, RpcScBootstrapSource,
    },
};
use cryptix_utils::triggers::SingleTrigger;
use hex::{decode as hex_decode, encode as hex_encode};
use std::{
    collections::{HashMap, HashSet},
    io::Write,
    net::{SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    sync::Mutex,
    time::{interval, timeout, MissedTickBehavior},
};

const SERVICE_IDENT: &str = "atomic-bootstrap-service";
const SNAPSHOT_MANIFEST_DOMAIN: &[u8] = b"CRYPTIX_ATOMIC_SNAPSHOT_MANIFEST_V1";
const SNAPSHOT_ID_DOMAIN: &[u8] = b"CAT_SNAPSHOT_ID_V1";
const MAX_REMOTE_SOURCES: usize = 64;
const RPC_CALL_TIMEOUT: Duration = Duration::from_secs(15);
const SOURCE_FAILURE_THRESHOLD: u32 = 3;
const SOURCE_BLOCK_DURATION: Duration = Duration::from_secs(300);
pub(crate) const ATOMIC_BOOTSTRAP_REQUIRED_SEED_SOURCES: usize = 1;
pub(crate) const ATOMIC_BOOTSTRAP_REQUIRED_NON_SEED_SOURCES: usize = 2;
pub(crate) const ATOMIC_BOOTSTRAP_REQUIRED_TOTAL_SOURCES: usize =
    ATOMIC_BOOTSTRAP_REQUIRED_SEED_SOURCES + ATOMIC_BOOTSTRAP_REQUIRED_NON_SEED_SOURCES;
const MAX_MANIFEST_HEX_LEN: usize = 4 * 1024 * 1024;
const MAX_ALLOWED_CHUNK_SIZE: u32 = 4 * 1024 * 1024;
const MAX_SNAPSHOT_FILE_SIZE_BYTES: u64 = MAX_BOOTSTRAP_SNAPSHOT_FILE_SIZE_BYTES;
const MAX_REPLAY_FILE_SIZE_BYTES: u64 = MAX_BOOTSTRAP_REPLAY_WINDOW_SIZE_BYTES;
const MAX_TOTAL_CHUNKS: usize = 65_536;
const HEALTH_AUDIT_INTERVAL: Duration = Duration::from_secs(60);
#[allow(dead_code)]
#[derive(Clone, Debug, BorshDeserialize)]
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

#[derive(Clone, Copy, Debug)]
struct SnapshotQuorumPolicy {
    allow_peer_majority_fallback: bool,
    require_seed_confirmed_if_any_seed: bool,
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
    last_health_audit: Mutex<Option<Instant>>,
    bootstrap_attempt_lock: Mutex<()>,
    source_penalties: Mutex<HashMap<String, SourcePenalty>>,
    allow_peer_majority_fallback_override: bool,
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
    ) -> Result<Self, String> {
        let retry_interval_sec = retry_interval_sec.max(5);
        if flow_context.config.net.is_mainnet() {
            if disable_dns_seed_sources && allow_peer_majority_fallback_override {
                warn!(
                    "[atomic-bootstrap] mainnet DNS seed bootstrap disabled by operator (--nodnsseed); peer-only fallback ENABLED by explicit override"
                );
            } else if disable_dns_seed_sources {
                warn!("[atomic-bootstrap] mainnet DNS seed bootstrap disabled by operator (--nodnsseed); peer-only fallback DISABLED");
            } else if allow_peer_majority_fallback_override {
                warn!("[atomic-bootstrap] mainnet peer-only fallback override ENABLED; used only when no seed source is reachable");
            } else {
                info!("[atomic-bootstrap] mainnet peer-only fallback override DISABLED");
            }
        }
        Ok(Self {
            atomic_token_service,
            flow_context,
            configured_rpc_peers,
            disable_dns_seed_sources,
            atomic_data_dir,
            retry_interval: Duration::from_secs(retry_interval_sec),
            last_health_audit: Default::default(),
            bootstrap_attempt_lock: Default::default(),
            source_penalties: Default::default(),
            allow_peer_majority_fallback_override,
            shutdown: Default::default(),
        })
    }

    fn snapshot_quorum_policy(&self) -> SnapshotQuorumPolicy {
        snapshot_quorum_policy_for_network(
            self.flow_context.config.net.is_mainnet(),
            self.disable_dns_seed_sources,
            self.allow_peer_majority_fallback_override,
        )
    }

    fn no_sources_reason(&self) -> String {
        if self.disable_dns_seed_sources {
            if self.flow_context.config.net.is_mainnet() && !self.allow_peer_majority_fallback_override {
                "no compatible bootstrap sources found (DNS seed bootstrap disabled by --nodnsseed; mainnet peer-only fallback is disabled unless --atomic-bootstrap-allow-peer-fallback is explicitly set)".to_string()
            } else {
                "no compatible bootstrap sources found (DNS seed bootstrap disabled by --nodnsseed; add manual peers and/or at least 3 independent --atomic-bootstrap-peer sources for peer-only quorum)".to_string()
            }
        } else {
            "no compatible bootstrap sources found".to_string()
        }
    }

    async fn should_run_health_audit(&self) -> bool {
        let now = Instant::now();
        let mut guard = self.last_health_audit.lock().await;
        if let Some(last) = *guard {
            if now.duration_since(last) < HEALTH_AUDIT_INTERVAL {
                return false;
            }
        }
        *guard = Some(now);
        true
    }

    async fn collect_compatible_sources(&self, protocol_version: u32, network_id: &str) -> Vec<SourceClient> {
        let mut sources: Vec<SourceClient> = Vec::new();
        let candidates = self.candidate_endpoints();

        for candidate in candidates.into_iter().take(MAX_REMOTE_SOURCES) {
            if self.is_source_blocked(&candidate.endpoint).await {
                trace!("[atomic-bootstrap] skipping temporarily blocked source {}", candidate.endpoint);
                continue;
            }

            let client = match timeout(RPC_CALL_TIMEOUT, GrpcClient::connect(candidate.endpoint.clone())).await {
                Ok(Ok(client)) => client,
                Ok(Err(err)) => {
                    self.record_source_failure(&candidate.endpoint).await;
                    trace!("[atomic-bootstrap] failed connecting to {}: {err}", candidate.endpoint);
                    continue;
                }
                Err(_) => {
                    self.record_source_failure(&candidate.endpoint).await;
                    trace!("[atomic-bootstrap] connect timeout for {}", candidate.endpoint);
                    continue;
                }
            };

            let head = match timeout(RPC_CALL_TIMEOUT, client.get_sc_snapshot_head()).await {
                Ok(Ok(response)) => match response.head {
                    Some(head) => head,
                    None => {
                        let _ = client.disconnect().await;
                        continue;
                    }
                },
                Ok(Err(err)) => {
                    self.record_source_failure(&candidate.endpoint).await;
                    trace!("[atomic-bootstrap] getScSnapshotHead failed on {}: {err}", candidate.endpoint);
                    let _ = client.disconnect().await;
                    continue;
                }
                Err(_) => {
                    self.record_source_failure(&candidate.endpoint).await;
                    trace!("[atomic-bootstrap] getScSnapshotHead timeout on {}", candidate.endpoint);
                    let _ = client.disconnect().await;
                    continue;
                }
            };

            if head.protocol_version != protocol_version || head.network_id != network_id {
                let _ = client.disconnect().await;
                continue;
            }

            let source_identity_bytes = match decode_hash32_hex(&head.node_identity) {
                Ok(identity) => identity,
                Err(err) => {
                    self.record_source_failure(&candidate.endpoint).await;
                    trace!(
                        "[atomic-bootstrap] getScSnapshotHead from {} has invalid/missing canonical node identity: {err}",
                        candidate.endpoint
                    );
                    let _ = client.disconnect().await;
                    continue;
                }
            };
            if let Some(expected_node_identity) = candidate.expected_node_identity {
                if expected_node_identity != source_identity_bytes {
                    self.record_source_failure(&candidate.endpoint).await;
                    trace!(
                        "[atomic-bootstrap] canonical node identity mismatch on {} (expected {}, got {})",
                        candidate.endpoint,
                        hex_encode(expected_node_identity),
                        hex_encode(source_identity_bytes)
                    );
                    let _ = client.disconnect().await;
                    continue;
                }
            }

            self.record_source_success(&candidate.endpoint).await;
            sources.push(SourceClient {
                endpoint: candidate.endpoint,
                source_identity: hex_encode(source_identity_bytes),
                kind: candidate.kind,
                client,
                head,
            });
        }

        sources
    }

    async fn verify_consensus_atomic_state_hash_quorum(
        &self,
        block_hash: BlockHash,
        expected_state_hash: [u8; 32],
    ) -> Result<(), String> {
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

        let manifest = match SnapshotManifestV1::try_from_slice(&manifest_bytes) {
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
            let manifest_bytes = self.fetch_manifest_bytes_with_quorum(&mut sources, &snapshot_id, required_votes).await?;
            let manifest = SnapshotManifestV1::try_from_slice(&manifest_bytes)
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

            self.atomic_token_service
                .import_snapshot_from_file(&snapshot_path)
                .await
                .map_err(|err| format!("snapshot import failed: {err}"))?;

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
        let health = self.atomic_token_service.get_health().await;
        let healthy_state = health.runtime_state == AtomicTokenRuntimeState::Healthy;
        let should_audit_healthy_state = if healthy_state { self.should_run_health_audit().await } else { false };
        if healthy_state && !should_audit_healthy_state {
            return Ok(false);
        }

        let protocol_version = self.atomic_token_service.protocol_version() as u32;
        let network_id = self.atomic_token_service.network_id().to_string();
        let sources = self.collect_compatible_sources(protocol_version, &network_id).await;

        if sources.is_empty() {
            let reason = self.no_sources_reason();
            if should_audit_healthy_state {
                trace!("[atomic-bootstrap] healthy-state audit skipped: {reason}");
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

        let default_rpc_port = self.flow_context.config.default_rpc_port();
        if !self.disable_dns_seed_sources {
            for &dns_seed in self.flow_context.config.dns_seeders {
                for endpoint in resolve_seed_endpoints(dns_seed, default_rpc_port) {
                    push_candidate_endpoint(&mut endpoints, &mut by_endpoint, endpoint, None, SourceKind::Seed);
                }
            }
        }

        for peer in self.flow_context.hub().active_peers() {
            let socket = SocketAddr::new(peer.net_address().ip(), default_rpc_port);
            let endpoint = format!("grpc://{socket}");
            push_candidate_endpoint(&mut endpoints, &mut by_endpoint, endpoint, peer.properties().unified_node_id, SourceKind::Peer);
        }

        // Include all known verified addresses.
        let address_manager = self.flow_context.address_manager.lock();
        for address in address_manager.iterate_verified_addresses() {
            let socket = SocketAddr::new(address.ip.into(), default_rpc_port);
            let endpoint = format!("grpc://{socket}");
            push_candidate_endpoint(&mut endpoints, &mut by_endpoint, endpoint, None, SourceKind::Peer);
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

    fn validate_manifest_sanity(&self, manifest: &SnapshotManifestV1) -> Result<(), String> {
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
        manifest: &SnapshotManifestV1,
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

        Ok(())
    }

    async fn download_and_verify_replay_window_to_file(
        &self,
        sources: &[SourceClient],
        snapshot_id: &str,
        manifest: &SnapshotManifestV1,
        output_path: &Path,
    ) -> Result<(), String> {
        let expected_total = manifest.replay_window_chunk_hashes.len() as u32;
        if expected_total == 0 {
            if manifest.replay_window_size != 0 {
                return Err("replay manifest has non-zero size but zero replay chunks".to_string());
            }
            std::fs::write(output_path, [])
                .map_err(|err| format!("failed writing empty replay window `{}`: {err}", output_path.display()))?;
            return Ok(());
        }

        let temp_path = output_path.with_extension("part");
        let mut file = std::fs::File::create(&temp_path)
            .map_err(|err| format!("failed creating replay download file `{}`: {err}", temp_path.display()))?;
        let mut replay_hasher = Blake2bParams::new().hash_length(32).to_state();
        replay_hasher.update(SNAPSHOT_MANIFEST_DOMAIN);
        let mut written = 0u64;
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
            entry.blocked_until = Some(Instant::now() + SOURCE_BLOCK_DURATION);
        }
    }
}

#[async_trait]
impl AtomicStateQuorumVerifier for AtomicBootstrapService {
    async fn verify_consensus_atomic_state_hash(&self, block_hash: BlockHash, state_hash: [u8; 32]) -> Result<(), String> {
        self.verify_consensus_atomic_state_hash_quorum(block_hash, state_hash).await
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
                                info!("[atomic-bootstrap] snapshot bootstrap completed successfully");
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

fn resolve_seed_endpoints(seed_host: &str, port: u16) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::<SocketAddr>::new();
    let lookup = format!("{seed_host}:{port}");
    if let Ok(resolved) = lookup.to_socket_addrs() {
        for socket in resolved {
            if seen.insert(socket) {
                out.push(format!("grpc://{socket}"));
            }
        }
    }

    if out.is_empty() {
        out.push(format!("grpc://{seed_host}:{port}"));
    }

    out
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

fn snapshot_quorum_policy_for_network(
    is_mainnet: bool,
    _disable_dns_seed_sources: bool,
    allow_peer_majority_fallback_override: bool,
) -> SnapshotQuorumPolicy {
    if is_mainnet {
        SnapshotQuorumPolicy {
            allow_peer_majority_fallback: allow_peer_majority_fallback_override,
            require_seed_confirmed_if_any_seed: true,
        }
    } else {
        SnapshotQuorumPolicy { allow_peer_majority_fallback: true, require_seed_confirmed_if_any_seed: false }
    }
}

fn select_snapshot_quorum(
    evidence: Vec<SnapshotSupportEvidence>,
    allow_peer_majority_fallback: bool,
    require_seed_confirmed_if_any_seed: bool,
) -> Result<SnapshotQuorumDecision, String> {
    #[derive(Clone, Debug)]
    struct SnapshotCandidate {
        snapshot_id: String,
        support: usize,
        seed_support: usize,
        non_seed_support: usize,
        best_daa: u64,
        best_block_hash: String,
    }

    let mut unique_sources = HashMap::<String, SnapshotSupportEvidence>::new();
    for mut source in evidence {
        if let Some(existing) = unique_sources.get_mut(&source.source_identity) {
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

        unique_sources.insert(source.source_identity.clone(), source);
    }

    let mut grouped: HashMap<String, Vec<SnapshotSupportEvidence>> = HashMap::new();
    for source in unique_sources.into_values() {
        grouped.entry(source.snapshot_id.to_ascii_lowercase()).or_default().push(source);
    }

    let mut total_seed_sources = 0usize;
    let mut total_non_seed_sources = 0usize;
    let mut candidates = grouped
        .into_iter()
        .map(|(snapshot_id, group_sources)| {
            let support = group_sources.len();
            let seed_support = group_sources.iter().filter(|s| matches!(s.kind, SourceKind::Seed)).count();
            let non_seed_support = support.saturating_sub(seed_support);
            total_seed_sources += seed_support;
            total_non_seed_sources += non_seed_support;
            let best_daa = group_sources.iter().map(|s| s.at_daa_score).max().unwrap_or(0);
            let best_block_hash = group_sources.iter().map(|s| s.at_block_hash.clone()).max().unwrap_or_default();

            SnapshotCandidate { snapshot_id, support, seed_support, non_seed_support, best_daa, best_block_hash }
        })
        .collect::<Vec<_>>();

    if candidates.is_empty() {
        return Err("no snapshot candidates available after grouping".to_string());
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

    if total_seed_sources > 0 {
        if let Some(selected) = candidates.iter().find(|candidate| {
            candidate.seed_support >= ATOMIC_BOOTSTRAP_REQUIRED_SEED_SOURCES
                && candidate.non_seed_support >= ATOMIC_BOOTSTRAP_REQUIRED_NON_SEED_SOURCES
        }) {
            return Ok(SnapshotQuorumDecision {
                snapshot_id: selected.snapshot_id.clone(),
                required_votes: ATOMIC_BOOTSTRAP_REQUIRED_TOTAL_SOURCES,
                policy_description: format!(
                    "seed-confirmed quorum (required: >={ATOMIC_BOOTSTRAP_REQUIRED_SEED_SOURCES} seed + >={ATOMIC_BOOTSTRAP_REQUIRED_NON_SEED_SOURCES} independent non-seeds; seed support: {}, non-seed support: {}, total support: {})",
                    selected.seed_support,
                    selected.non_seed_support,
                    selected.support
                ),
            });
        }

        seed_quorum_failure = Some(format!(
            "seed-confirmed bootstrap quorum not reached: found {total_seed_sources} reachable seed source(s) but no snapshot matched by >={ATOMIC_BOOTSTRAP_REQUIRED_SEED_SOURCES} seed plus >={ATOMIC_BOOTSTRAP_REQUIRED_NON_SEED_SOURCES} independent non-seed sources"
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

    if total_non_seed_sources < ATOMIC_BOOTSTRAP_REQUIRED_TOTAL_SOURCES {
        let fallback_err = format!(
            "peer-majority bootstrap unavailable: only {total_non_seed_sources} independent non-seed source(s) available (minimum required: {ATOMIC_BOOTSTRAP_REQUIRED_TOTAL_SOURCES})"
        );
        return Err(match seed_quorum_failure {
            Some(seed_err) => format!("{seed_err}; {fallback_err}"),
            None => fallback_err,
        });
    }

    let required_votes = (total_non_seed_sources / 2) + 1;
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
            "peer-majority bootstrap quorum not reached for `{}` (required votes: {required_votes}, matching non-seed sources: {}, total non-seed sources: {total_non_seed_sources})",
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
            "{fallback_reason} (matching non-seed sources: {}/{total_non_seed_sources}, total support: {})",
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
        ATOMIC_BOOTSTRAP_REQUIRED_NON_SEED_SOURCES, ATOMIC_BOOTSTRAP_REQUIRED_SEED_SOURCES, ATOMIC_BOOTSTRAP_REQUIRED_TOTAL_SOURCES,
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
        )
        .expect("seed + two additional sources should satisfy quorum");

        assert_eq!(decision.snapshot_id, "snapshot-a");
        assert_eq!(decision.required_votes, ATOMIC_BOOTSTRAP_REQUIRED_TOTAL_SOURCES);
        assert!(decision.policy_description.contains("seed-confirmed quorum"));
        assert!(decision.policy_description.contains(&format!(
            ">={ATOMIC_BOOTSTRAP_REQUIRED_SEED_SOURCES} seed + >={ATOMIC_BOOTSTRAP_REQUIRED_NON_SEED_SOURCES} independent non-seeds"
        )));
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
        )
        .expect_err("seed + one non-seed must not satisfy seed-confirmed quorum");

        assert!(err.contains("seed-confirmed bootstrap quorum not reached"), "unexpected error message: {err}");
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
        )
        .expect_err("without seed, fewer than three non-seed sources must fail");

        assert!(
            err.contains(&format!("minimum required: {ATOMIC_BOOTSTRAP_REQUIRED_TOTAL_SOURCES}")),
            "unexpected error message: {err}"
        );
    }

    #[test]
    fn quorum_policy_peer_majority_without_seed_accepts_three_sources() {
        let decision = select_snapshot_quorum(
            vec![
                evidence("peer-1", "snapshot-x", SourceKind::Peer, 220, "xxxx"),
                evidence("peer-2", "snapshot-x", SourceKind::Configured, 220, "xxxx"),
                evidence("peer-3", "snapshot-y", SourceKind::Peer, 219, "yyyy"),
            ],
            true,
            true,
        )
        .expect("2 of 3 non-seed sources should satisfy peer-majority quorum");

        assert_eq!(decision.snapshot_id, "snapshot-x");
        assert_eq!(decision.required_votes, 2);
        assert!(decision.policy_description.contains("peer-majority quorum"));
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
        )
        .expect_err("peer-majority fallback should be rejected when disabled by policy");

        assert!(err.contains("peer-majority bootstrap disabled by policy"), "unexpected error message: {err}");
    }

    #[test]
    fn network_policy_mainnet_defaults_to_strict_seed_mode() {
        let policy = snapshot_quorum_policy_for_network(true, false, false);

        assert!(!policy.allow_peer_majority_fallback);
        assert!(policy.require_seed_confirmed_if_any_seed);
    }

    #[test]
    fn network_policy_mainnet_nodnsseed_keeps_peer_majority_disabled_by_default() {
        let policy = snapshot_quorum_policy_for_network(true, true, false);

        assert!(!policy.allow_peer_majority_fallback);
        assert!(policy.require_seed_confirmed_if_any_seed);
    }

    #[test]
    fn network_policy_mainnet_peer_fallback_requires_explicit_override() {
        let policy = snapshot_quorum_policy_for_network(true, true, true);

        assert!(policy.allow_peer_majority_fallback);
        assert!(policy.require_seed_confirmed_if_any_seed);
    }

    #[test]
    fn network_policy_non_mainnet_allows_peer_majority_mode() {
        let policy = snapshot_quorum_policy_for_network(false, false, false);

        assert!(policy.allow_peer_majority_fallback);
        assert!(!policy.require_seed_confirmed_if_any_seed);
    }
}
