use borsh::BorshSerialize;
use cryptix_core::time::unix_now;
use cryptix_core::{info, warn};
use cryptix_p2p_lib::pb::StrongNodeAnnouncementMessage;
use hex::{decode as hex_decode, encode as hex_encode};
use parking_lot::Mutex;
use prost::Message;
use secp256k1::{schnorr::Signature, Keypair, Message as SecpMessage, SecretKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

pub const STRONG_NODES_P2P_SERVICE_BIT: u64 = 1 << 21;

const ANNOUNCEMENT_SCHEMA_VERSION: u32 = 1;
const ANNOUNCEMENT_MAX_BYTES: usize = 2048;
const ANNOUNCEMENT_ACCEPT_AGE_MS: u64 = 20 * 60 * 1000;
const ANNOUNCEMENT_FUTURE_SKEW_MS: u64 = 2 * 60 * 1000;
const ANNOUNCEMENT_WINDOW_MS: u64 = 10 * 60 * 1000;
const ANNOUNCEMENT_WINDOW_TOLERANCE_MS: u64 = 30 * 1000;

const REGISTRY_CAP: usize = 2048;
const REGISTRY_TTL_MS: u64 = 20 * 60 * 1000;

const EVAL_INTERVAL_MS: u64 = 60 * 1000;
const ANNOUNCE_INTERVAL_MS: u64 = 180 * 1000;

const FLUSH_DEBOUNCE_MS: u64 = 30 * 1000;
const FLUSH_MAX_INTERVAL_MS: u64 = 60 * 1000;

const INBOUND_RATE_WINDOW_MS: u64 = 1000;
const INBOUND_RATE_MAX_MSGS_PER_WINDOW: u32 = 32;
const INBOUND_RATE_MAX_TRACKED_SENDERS: usize = 4096;
const INBOUND_NEW_IDS_WINDOW_MS: u64 = 10 * 60 * 1000;
const INBOUND_NEW_IDS_MAX_PER_WINDOW: usize = 128;
const INBOUND_NEW_IDS_MAX_TRACKED_SENDERS: usize = 4096;

const INTERNAL_ERROR_WINDOW_MS: u64 = 10 * 60 * 1000;
const INTERNAL_ERROR_THRESHOLD: usize = 5;

const IDENTITY_FILE_MAX_BYTES: usize = 16 * 1024;
const REGISTRY_FILE_MAX_BYTES: usize = 4 * 1024 * 1024;

const STRONG_NODES_DIR: &str = "strong-nodes";
const NODE_IDENTITY_FILE: &str = "node_identity.json";
const REGISTRY_FILE: &str = "strong_nodes_registry.json";
const DOMAIN_TAG: &[u8] = b"StrongNodeAnnouncement/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DisabledReasonCode {
    ConfigDisabled,
    HardforkInactive,
    InitFailed,
    PersistenceFailed,
    CircuitBreakerOpen,
}

impl DisabledReasonCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfigDisabled => "CONFIG_DISABLED",
            Self::HardforkInactive => "HARDFORK_INACTIVE",
            Self::InitFailed => "INIT_FAILED",
            Self::PersistenceFailed => "PERSISTENCE_FAILED",
            Self::CircuitBreakerOpen => "CIRCUIT_BREAKER_OPEN",
        }
    }
}

#[derive(Clone, Debug)]
pub struct StrongNodesRuntimeSnapshot {
    pub enabled_by_config: bool,
    pub hardfork_active: bool,
    pub runtime_available: bool,
    pub disabled_reason_code: Option<DisabledReasonCode>,
    pub disabled_reason_message: Option<String>,
    pub seq_conflict_total: u64,
    pub nodes: Vec<StrongNodeEntrySnapshot>,
}

#[derive(Clone, Debug)]
pub struct StrongNodeEntrySnapshot {
    pub static_id: String,
    pub public_key_xonly: String,
    pub source: String,
    pub signature_valid: bool,
    pub performance_verified: bool,
    pub claimed_ip: Option<String>,
    pub last_sender_ip: Option<String>,
    pub seq_no: u64,
    pub found_blocks_10m: u32,
    pub total_blocks_10m: u32,
    pub share_bps: u32,
    pub window_start_ms: u64,
    pub window_end_ms: u64,
    pub sent_at_ms: u64,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub last_announce_sent_at_ms: u64,
    pub is_stale: bool,
}

#[derive(Clone, Debug)]
pub struct StrongNodesEngineConfig {
    pub enabled: bool,
    pub network: String,
    pub app_data_dir: PathBuf,
}

#[derive(Clone, Debug, Default)]
pub struct TickOutput {
    pub outbound_announcement: Option<StrongNodeAnnouncementMessage>,
}

#[derive(Clone, Debug)]
pub enum IngestOutcome {
    Ignored,
    Dropped,
    Accepted,
    Strike { reason: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct NodeIdentityDisk {
    schema_version: u32,
    secret_key: String,
    public_key_xonly: String,
    static_id_raw: String,
    last_seq_no: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RegistryDisk {
    schema_version: u32,
    entries: Vec<RegistryEntryDisk>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RegistryEntryDisk {
    static_id_raw: String,
    pubkey_xonly: String,
    seq_no: u64,
    window_start_ms: u64,
    window_end_ms: u64,
    found_blocks_10m: u32,
    total_blocks_10m: u32,
    sent_at_ms: u64,
    claimed_ip: Option<String>,
    last_sender_ip: Option<String>,
    source: String,
    signature_valid: bool,
    payload_hash: String,
    #[serde(default)]
    first_seen_ms: Option<u64>,
    last_seen_ms: u64,
}

#[derive(Clone, Debug)]
struct NodeIdentity {
    secret_key: SecretKey,
    pubkey_xonly: [u8; 32],
    static_id_raw: [u8; 32],
    last_seq_no: u64,
}

#[derive(Clone, Copy, Debug)]
struct BlockSample {
    now_ms: u64,
    found: bool,
}

#[derive(Clone, Debug)]
struct RegistryEntry {
    static_id_raw: [u8; 32],
    pubkey_xonly: [u8; 32],
    seq_no: u64,
    window_start_ms: u64,
    window_end_ms: u64,
    found_blocks_10m: u32,
    total_blocks_10m: u32,
    sent_at_ms: u64,
    claimed_ip: Option<IpAddr>,
    last_sender_ip: Option<IpAddr>,
    source: EntrySource,
    signature_valid: bool,
    payload_hash: [u8; 32],
    first_seen_ms: u64,
    last_seen_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntrySource {
    SelfNode,
    Direct,
    Gossip,
}

impl EntrySource {
    fn as_str(self) -> &'static str {
        match self {
            Self::SelfNode => "self",
            Self::Direct => "direct",
            Self::Gossip => "gossip",
        }
    }

    fn from_str(value: &str) -> Self {
        match value {
            "self" => Self::SelfNode,
            "gossip" => Self::Gossip,
            _ => Self::Direct,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct QualificationState {
    qualified: bool,
    qualify_streak: u8,
    dequalify_streak: u8,
}

#[derive(Clone, Copy, Debug, Default)]
struct InboundRateRecord {
    window_start_ms: u64,
    msgs_in_window: u32,
    last_seen_ms: u64,
}

#[derive(Clone, Debug, Default)]
struct InboundNewIdsRecord {
    window_start_ms: u64,
    ids_in_window: BTreeSet<[u8; 32]>,
    last_seen_ms: u64,
}

#[derive(Default)]
struct EngineState {
    identity: Option<NodeIdentity>,
    registry: BTreeMap<[u8; 32], RegistryEntry>,
    block_samples_10m: VecDeque<BlockSample>,
    qualification: QualificationState,
    last_eval_ms: u64,
    last_announce_ms: u64,
    dirty: bool,
    dirty_since_ms: Option<u64>,
    last_flush_ms: u64,
    disabled_reason_code: Option<DisabledReasonCode>,
    disabled_reason_message: Option<String>,
    internal_error_timestamps: VecDeque<u64>,
    inbound_rate_by_sender: BTreeMap<IpAddr, InboundRateRecord>,
    inbound_new_ids_by_sender: BTreeMap<IpAddr, InboundNewIdsRecord>,
    seq_conflict_total: u64,
}

pub struct StrongNodesEngine {
    config: StrongNodesEngineConfig,
    strong_nodes_dir: PathBuf,
    state: Mutex<EngineState>,
}

#[derive(BorshSerialize)]
struct AnnouncementPreimage {
    domain_tag: Vec<u8>,
    schema_version: u32,
    network: String,
    static_id_raw: [u8; 32],
    pubkey_xonly: [u8; 32],
    seq_no: u64,
    window_start_ms: u64,
    window_end_ms: u64,
    found_blocks_10m: u32,
    total_blocks_10m: u32,
    sent_at_ms: u64,
    claimed_ip: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
struct WindowStats {
    found: u32,
    total: u32,
    window_start_ms: u64,
    window_end_ms: u64,
}

impl StrongNodesEngine {
    pub fn new(config: StrongNodesEngineConfig) -> Self {
        let strong_nodes_dir = config.app_data_dir.join(STRONG_NODES_DIR);
        let mut state = EngineState::default();

        if !config.enabled {
            state.disabled_reason_code = Some(DisabledReasonCode::ConfigDisabled);
            state.disabled_reason_message = Some("feature disabled by config/CLI".to_string());
            return Self { config, strong_nodes_dir, state: Mutex::new(state) };
        }

        if let Err(err) = fs::create_dir_all(&strong_nodes_dir) {
            state.disabled_reason_code = Some(DisabledReasonCode::InitFailed);
            state.disabled_reason_message = Some(format!("failed creating strong-nodes directory: {err}"));
            return Self { config, strong_nodes_dir, state: Mutex::new(state) };
        }

        let identity = match load_or_create_identity(&strong_nodes_dir) {
            Ok(identity) => Some(identity),
            Err(err) => {
                state.disabled_reason_code = Some(DisabledReasonCode::InitFailed);
                state.disabled_reason_message = Some(err);
                None
            }
        };

        let registry = match load_registry(&strong_nodes_dir) {
            Ok(registry) => registry,
            Err(err) => {
                warn!("strong-nodes: registry load failed, starting from empty registry: {err}");
                BTreeMap::new()
            }
        };

        state.identity = identity;
        state.registry = registry;
        state.last_flush_ms = unix_now();

        Self { config, strong_nodes_dir, state: Mutex::new(state) }
    }

    pub fn enabled_by_config(&self) -> bool {
        self.config.enabled
    }

    pub fn should_advertise_service_bit(&self, hardfork_active: bool) -> bool {
        let state = self.state.lock();
        self.runtime_available_locked(&state, hardfork_active)
    }

    pub fn on_block_event(&self, found_by_local_node: bool) {
        let now_ms = unix_now();
        let mut state = self.state.lock();
        if state.disabled_reason_code.is_some() {
            return;
        }
        state.block_samples_10m.push_back(BlockSample { now_ms, found: found_by_local_node });
        prune_samples(&mut state.block_samples_10m, now_ms);
    }

    pub fn on_tick(&self, hardfork_active: bool, claimed_ip: Option<IpAddr>) -> TickOutput {
        let now_ms = unix_now();
        let mut state = self.state.lock();
        let mut output = TickOutput::default();

        prune_samples(&mut state.block_samples_10m, now_ms);
        if evict_stale_registry(&mut state.registry, now_ms) {
            mark_dirty(&mut state, now_ms);
        }
        trim_inbound_rate_cache(&mut state.inbound_rate_by_sender, now_ms);
        trim_inbound_new_ids_cache(&mut state.inbound_new_ids_by_sender, now_ms);

        if !self.runtime_available_locked(&state, hardfork_active) {
            if let Err(err) = maybe_flush_registry_locked(&self.strong_nodes_dir, &mut state, now_ms) {
                self.disable_runtime_locked(
                    &mut state,
                    DisabledReasonCode::PersistenceFailed,
                    format!("failed persisting strong-nodes registry: {err}"),
                );
            }
            return output;
        }

        if should_evaluate(now_ms, state.last_eval_ms) {
            evaluate_qualification(&mut state, now_ms);
            state.last_eval_ms = now_ms;
        }

        if should_announce(now_ms, state.last_announce_ms, state.qualification.qualified) {
            if let Some(identity) = state.identity.clone() {
                match build_signed_announcement(
                    &identity,
                    &self.config.network,
                    claimed_ip,
                    window_stats(&state.block_samples_10m, now_ms),
                ) {
                    Ok((announcement, payload_hash)) => {
                        if let Err(err) = self.persist_identity_with_incremented_seq_locked(&mut state) {
                            self.disable_runtime_locked(
                                &mut state,
                                DisabledReasonCode::PersistenceFailed,
                                format!("failed persisting node identity: {err}"),
                            );
                        } else {
                            state.last_announce_ms = now_ms;
                            apply_self_announcement_to_registry(&mut state, &announcement, payload_hash, now_ms);
                            mark_dirty(&mut state, now_ms);
                            output.outbound_announcement = Some(announcement);
                        }
                    }
                    Err(err) => {
                        self.record_internal_error_locked(&mut state, format!("self announcement build failed: {err}"), now_ms)
                    }
                }
            } else {
                self.disable_runtime_locked(
                    &mut state,
                    DisabledReasonCode::InitFailed,
                    "missing node identity while announcing".to_string(),
                );
            }
        }

        if let Err(err) = maybe_flush_registry_locked(&self.strong_nodes_dir, &mut state, now_ms) {
            self.disable_runtime_locked(
                &mut state,
                DisabledReasonCode::PersistenceFailed,
                format!("failed persisting strong-nodes registry: {err}"),
            );
        }
        output
    }

    pub fn ingest_announcement(
        &self,
        message: &StrongNodeAnnouncementMessage,
        sender_ip: IpAddr,
        hardfork_active: bool,
    ) -> IngestOutcome {
        let now_ms = unix_now();
        let mut state = self.state.lock();

        if !self.runtime_available_locked(&state, hardfork_active) {
            return IngestOutcome::Ignored;
        }

        if !allow_sender_rate(&mut state, sender_ip, now_ms) {
            return IngestOutcome::Dropped;
        }
        if let Some(static_id_hint) = bytes_to_array_32(&message.static_id_raw) {
            if !state.registry.contains_key(&static_id_hint)
                && !allow_sender_new_id(
                    &mut state,
                    sender_ip,
                    static_id_hint,
                    now_ms,
                    INBOUND_NEW_IDS_WINDOW_MS,
                    INBOUND_NEW_IDS_MAX_PER_WINDOW,
                )
            {
                return IngestOutcome::Dropped;
            }
        }

        match validate_and_transform_announcement(message, &self.config.network, now_ms) {
            Ok(verified) => {
                let self_static_id = state.identity.as_ref().map(|identity| identity.static_id_raw);
                if Some(verified.static_id_raw) == self_static_id {
                    return IngestOutcome::Dropped;
                }

                if let Some(current) = state.registry.get(&verified.static_id_raw) {
                    if verified.seq_no < current.seq_no {
                        return IngestOutcome::Dropped;
                    }
                    if verified.seq_no == current.seq_no {
                        if verified.payload_hash == current.payload_hash {
                            return IngestOutcome::Dropped;
                        }
                        state.seq_conflict_total = state.seq_conflict_total.saturating_add(1);
                        return IngestOutcome::Strike {
                            reason: "strong-nodes seq conflict for same static_id and seq_no".to_string(),
                        };
                    }
                }

                upsert_registry_entry(&mut state, verified, sender_ip, now_ms);
                mark_dirty(&mut state, now_ms);
                IngestOutcome::Accepted
            }
            Err(_) => IngestOutcome::Dropped,
        }
    }

    pub fn snapshot(&self, hardfork_active: bool) -> StrongNodesRuntimeSnapshot {
        let now_ms = unix_now();
        let state = self.state.lock();
        let runtime_available = self.runtime_available_locked(&state, hardfork_active);
        let disabled_reason_code = if !self.config.enabled {
            Some(DisabledReasonCode::ConfigDisabled)
        } else if !hardfork_active {
            Some(DisabledReasonCode::HardforkInactive)
        } else {
            state.disabled_reason_code
        };
        let disabled_reason_message = if !self.config.enabled {
            Some("feature disabled by config/CLI".to_string())
        } else if !hardfork_active {
            Some("payload hardfork is not active yet".to_string())
        } else {
            state.disabled_reason_message.clone()
        };

        let mut nodes = state.registry.values().map(|entry| entry_to_snapshot(entry, now_ms)).collect::<Vec<_>>();
        nodes.sort_by(|a, b| b.last_seen_ms.cmp(&a.last_seen_ms).then_with(|| a.static_id.cmp(&b.static_id)));

        StrongNodesRuntimeSnapshot {
            enabled_by_config: self.config.enabled,
            hardfork_active,
            runtime_available,
            disabled_reason_code,
            disabled_reason_message,
            seq_conflict_total: state.seq_conflict_total,
            nodes,
        }
    }

    pub fn best_effort_flush(&self) {
        let now_ms = unix_now();
        let mut state = self.state.lock();
        let _ = maybe_flush_registry_locked(&self.strong_nodes_dir, &mut state, now_ms.saturating_add(FLUSH_MAX_INTERVAL_MS));
    }

    fn runtime_available_locked(&self, state: &EngineState, hardfork_active: bool) -> bool {
        self.config.enabled && hardfork_active && state.disabled_reason_code.is_none() && state.identity.is_some()
    }

    fn disable_runtime_locked(&self, state: &mut EngineState, code: DisabledReasonCode, message: String) {
        if state.disabled_reason_code.is_none() {
            warn!("strong-nodes: disabling module due to {} ({message})", code.as_str());
            state.disabled_reason_code = Some(code);
            state.disabled_reason_message = Some(message);
        }
    }

    fn record_internal_error_locked(&self, state: &mut EngineState, message: String, now_ms: u64) {
        warn!("strong-nodes: internal error: {message}");
        state.internal_error_timestamps.push_back(now_ms);
        while let Some(front) = state.internal_error_timestamps.front().copied() {
            if now_ms.saturating_sub(front) > INTERNAL_ERROR_WINDOW_MS {
                state.internal_error_timestamps.pop_front();
            } else {
                break;
            }
        }
        if state.internal_error_timestamps.len() >= INTERNAL_ERROR_THRESHOLD {
            self.disable_runtime_locked(
                state,
                DisabledReasonCode::CircuitBreakerOpen,
                format!(
                    "circuit breaker opened after {} internal errors within {} seconds",
                    INTERNAL_ERROR_THRESHOLD,
                    INTERNAL_ERROR_WINDOW_MS / 1000
                ),
            );
        }
    }

    fn persist_identity_with_incremented_seq_locked(&self, state: &mut EngineState) -> Result<(), String> {
        let identity = state.identity.as_mut().ok_or_else(|| "identity is missing".to_string())?;
        identity.last_seq_no = identity.last_seq_no.saturating_add(1);
        if let Err(err) = persist_identity(&self.strong_nodes_dir, identity) {
            identity.last_seq_no = identity.last_seq_no.saturating_sub(1);
            return Err(err);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct VerifiedAnnouncement {
    static_id_raw: [u8; 32],
    pubkey_xonly: [u8; 32],
    seq_no: u64,
    window_start_ms: u64,
    window_end_ms: u64,
    found_blocks_10m: u32,
    total_blocks_10m: u32,
    sent_at_ms: u64,
    claimed_ip: Option<IpAddr>,
    payload_hash: [u8; 32],
}

#[derive(Debug)]
enum ValidationError {
    Malformed,
    WrongNetwork,
    InvalidSchema,
    Oversized,
    InvalidIpEncoding,
    InvalidWindow,
    InvalidSignature,
    InvalidStaticId,
}

fn apply_self_announcement_to_registry(
    state: &mut EngineState,
    message: &StrongNodeAnnouncementMessage,
    payload_hash: [u8; 32],
    now_ms: u64,
) {
    let Some(static_id_raw) = bytes_to_array_32(&message.static_id_raw) else {
        return;
    };
    let Some(pubkey_xonly) = bytes_to_array_32(&message.pubkey_xonly) else {
        return;
    };
    let claimed_ip = parse_claimed_ip_bytes(&message.claimed_ip).ok().flatten();
    let first_seen_ms = state.registry.get(&static_id_raw).map(|entry| entry.first_seen_ms).unwrap_or(now_ms);
    let entry = RegistryEntry {
        static_id_raw,
        pubkey_xonly,
        seq_no: message.seq_no,
        window_start_ms: message.window_start_ms,
        window_end_ms: message.window_end_ms,
        found_blocks_10m: message.found_blocks10m,
        total_blocks_10m: message.total_blocks10m,
        sent_at_ms: message.sent_at_ms,
        claimed_ip,
        last_sender_ip: None,
        source: EntrySource::SelfNode,
        signature_valid: true,
        payload_hash,
        first_seen_ms,
        last_seen_ms: now_ms,
    };
    state.registry.insert(static_id_raw, entry);
    evict_registry_overflow(&mut state.registry);
}

fn upsert_registry_entry(state: &mut EngineState, verified: VerifiedAnnouncement, sender_ip: IpAddr, now_ms: u64) {
    let source = if verified.claimed_ip == Some(sender_ip) { EntrySource::Direct } else { EntrySource::Gossip };
    let first_seen_ms = state.registry.get(&verified.static_id_raw).map(|entry| entry.first_seen_ms).unwrap_or(now_ms);
    let entry = RegistryEntry {
        static_id_raw: verified.static_id_raw,
        pubkey_xonly: verified.pubkey_xonly,
        seq_no: verified.seq_no,
        window_start_ms: verified.window_start_ms,
        window_end_ms: verified.window_end_ms,
        found_blocks_10m: verified.found_blocks_10m,
        total_blocks_10m: verified.total_blocks_10m,
        sent_at_ms: verified.sent_at_ms,
        claimed_ip: verified.claimed_ip,
        last_sender_ip: Some(sender_ip),
        source,
        signature_valid: true,
        payload_hash: verified.payload_hash,
        first_seen_ms,
        last_seen_ms: now_ms,
    };
    state.registry.insert(verified.static_id_raw, entry);
    evict_registry_overflow(&mut state.registry);
}

fn entry_to_snapshot(entry: &RegistryEntry, now_ms: u64) -> StrongNodeEntrySnapshot {
    let share_bps = if entry.total_blocks_10m == 0 {
        0
    } else {
        ((entry.found_blocks_10m as u64 * 10_000) / entry.total_blocks_10m as u64) as u32
    };
    StrongNodeEntrySnapshot {
        static_id: hex_encode(entry.static_id_raw),
        public_key_xonly: hex_encode(entry.pubkey_xonly),
        source: entry.source.as_str().to_string(),
        signature_valid: entry.signature_valid,
        performance_verified: false,
        claimed_ip: entry.claimed_ip.map(ip_to_canonical_string),
        last_sender_ip: entry.last_sender_ip.map(ip_to_canonical_string),
        seq_no: entry.seq_no,
        found_blocks_10m: entry.found_blocks_10m,
        total_blocks_10m: entry.total_blocks_10m,
        share_bps,
        window_start_ms: entry.window_start_ms,
        window_end_ms: entry.window_end_ms,
        sent_at_ms: entry.sent_at_ms,
        first_seen_ms: entry.first_seen_ms,
        last_seen_ms: entry.last_seen_ms,
        last_announce_sent_at_ms: entry.sent_at_ms,
        is_stale: now_ms.saturating_sub(entry.last_seen_ms) > REGISTRY_TTL_MS,
    }
}

fn maybe_flush_registry_locked(strong_nodes_dir: &Path, state: &mut EngineState, now_ms: u64) -> Result<(), String> {
    if !state.dirty {
        return Ok(());
    }

    let dirty_since_ms = state.dirty_since_ms.unwrap_or(now_ms);
    let debounce_elapsed = now_ms.saturating_sub(dirty_since_ms) >= FLUSH_DEBOUNCE_MS;
    let hard_flush_due = now_ms.saturating_sub(state.last_flush_ms) >= FLUSH_MAX_INTERVAL_MS;
    if !(debounce_elapsed || hard_flush_due) {
        return Ok(());
    }

    persist_registry(strong_nodes_dir, &state.registry)?;
    state.dirty = false;
    state.dirty_since_ms = None;
    state.last_flush_ms = now_ms;
    Ok(())
}

fn mark_dirty(state: &mut EngineState, now_ms: u64) {
    if !state.dirty {
        state.dirty = true;
        state.dirty_since_ms = Some(now_ms);
    }
}

fn should_evaluate(now_ms: u64, last_eval_ms: u64) -> bool {
    last_eval_ms == 0 || now_ms.saturating_sub(last_eval_ms) >= EVAL_INTERVAL_MS
}

fn should_announce(now_ms: u64, last_announce_ms: u64, qualified: bool) -> bool {
    qualified && (last_announce_ms == 0 || now_ms.saturating_sub(last_announce_ms) >= ANNOUNCE_INTERVAL_MS)
}

fn window_stats(samples: &VecDeque<BlockSample>, now_ms: u64) -> WindowStats {
    if samples.is_empty() {
        return WindowStats {
            found: 0,
            total: 0,
            window_start_ms: now_ms.saturating_sub(ANNOUNCEMENT_WINDOW_MS),
            window_end_ms: now_ms,
        };
    }

    let found = samples.iter().filter(|sample| sample.found).count() as u32;
    let total = samples.len() as u32;
    let first_ts = samples.front().map(|sample| sample.now_ms).unwrap_or(now_ms);
    let window_start_ms = first_ts.max(now_ms.saturating_sub(ANNOUNCEMENT_WINDOW_MS));
    WindowStats { found, total, window_start_ms, window_end_ms: now_ms }
}

fn evaluate_qualification(state: &mut EngineState, now_ms: u64) {
    let stats = window_stats(&state.block_samples_10m, now_ms);
    let share = if stats.total == 0 { 0.0 } else { stats.found as f64 / stats.total as f64 };
    let qualifies = share > 0.10 && stats.total >= 60 && stats.found >= 3;
    let dequalifies = share < 0.08 || stats.total < 60 || stats.found < 3;

    if !state.qualification.qualified {
        if qualifies {
            state.qualification.qualify_streak = state.qualification.qualify_streak.saturating_add(1);
            if state.qualification.qualify_streak >= 2 {
                state.qualification.qualified = true;
                state.qualification.dequalify_streak = 0;
                info!("strong-nodes: local node qualified (found={} total={} share={:.2}%)", stats.found, stats.total, share * 100.0);
            }
        } else {
            state.qualification.qualify_streak = 0;
        }
        return;
    }

    if dequalifies {
        state.qualification.dequalify_streak = state.qualification.dequalify_streak.saturating_add(1);
        if state.qualification.dequalify_streak >= 2 {
            state.qualification.qualified = false;
            state.qualification.qualify_streak = 0;
            info!("strong-nodes: local node dequalified (found={} total={} share={:.2}%)", stats.found, stats.total, share * 100.0);
        }
    } else {
        state.qualification.dequalify_streak = 0;
    }
}

fn validate_and_transform_announcement(
    message: &StrongNodeAnnouncementMessage,
    expected_network: &str,
    now_ms: u64,
) -> Result<VerifiedAnnouncement, ValidationError> {
    if message.encoded_len() > ANNOUNCEMENT_MAX_BYTES {
        return Err(ValidationError::Oversized);
    }
    if message.schema_version != ANNOUNCEMENT_SCHEMA_VERSION {
        return Err(ValidationError::InvalidSchema);
    }
    if message.network != expected_network {
        return Err(ValidationError::WrongNetwork);
    }

    let static_id_raw = bytes_to_array_32(&message.static_id_raw).ok_or(ValidationError::Malformed)?;
    let pubkey_xonly = bytes_to_array_32(&message.pubkey_xonly).ok_or(ValidationError::Malformed)?;
    if message.signature.len() != 64 {
        return Err(ValidationError::Malformed);
    }
    let claimed_ip = parse_claimed_ip_bytes(&message.claimed_ip).map_err(|_| ValidationError::InvalidIpEncoding)?;

    if message.window_end_ms < message.window_start_ms {
        return Err(ValidationError::InvalidWindow);
    }
    let window_len = message.window_end_ms.saturating_sub(message.window_start_ms);
    if window_len > ANNOUNCEMENT_WINDOW_MS.saturating_add(ANNOUNCEMENT_WINDOW_TOLERANCE_MS) {
        return Err(ValidationError::InvalidWindow);
    }
    if now_ms.saturating_add(ANNOUNCEMENT_FUTURE_SKEW_MS) < message.sent_at_ms {
        return Err(ValidationError::InvalidWindow);
    }
    if now_ms.saturating_sub(message.sent_at_ms) > ANNOUNCEMENT_ACCEPT_AGE_MS {
        return Err(ValidationError::InvalidWindow);
    }
    if message.sent_at_ms.saturating_add(ANNOUNCEMENT_WINDOW_TOLERANCE_MS) < message.window_end_ms {
        return Err(ValidationError::InvalidWindow);
    }

    let digest = blake3::hash(&pubkey_xonly);
    if static_id_raw != *digest.as_bytes() {
        return Err(ValidationError::InvalidStaticId);
    }

    let preimage = preimage_bytes_from_message(message)?;
    let payload_hash = *blake3::hash(&preimage).as_bytes();
    verify_signature(&preimage, &pubkey_xonly, &message.signature)?;

    Ok(VerifiedAnnouncement {
        static_id_raw,
        pubkey_xonly,
        seq_no: message.seq_no,
        window_start_ms: message.window_start_ms,
        window_end_ms: message.window_end_ms,
        found_blocks_10m: message.found_blocks10m,
        total_blocks_10m: message.total_blocks10m,
        sent_at_ms: message.sent_at_ms,
        claimed_ip,
        payload_hash,
    })
}

fn build_signed_announcement(
    identity: &NodeIdentity,
    network: &str,
    claimed_ip: Option<IpAddr>,
    stats: WindowStats,
) -> Result<(StrongNodeAnnouncementMessage, [u8; 32]), String> {
    let seq_no = identity.last_seq_no.saturating_add(1);
    let claimed_ip_bytes = claimed_ip.map(canonicalize_claimed_ip).unwrap_or_default();
    let mut announcement = StrongNodeAnnouncementMessage {
        schema_version: ANNOUNCEMENT_SCHEMA_VERSION,
        network: network.to_string(),
        static_id_raw: identity.static_id_raw.to_vec(),
        pubkey_xonly: identity.pubkey_xonly.to_vec(),
        seq_no,
        window_start_ms: stats.window_start_ms,
        window_end_ms: stats.window_end_ms,
        found_blocks10m: stats.found,
        total_blocks10m: stats.total,
        sent_at_ms: unix_now(),
        claimed_ip: claimed_ip_bytes,
        signature: Vec::new(),
    };
    let preimage = preimage_bytes_from_message(&announcement).map_err(|_| "failed serializing announcement preimage".to_string())?;
    let payload_hash = *blake3::hash(&preimage).as_bytes();
    let signature = sign_preimage(&preimage, &identity.secret_key).map_err(|err| format!("sign failed: {err}"))?;
    announcement.signature = signature;
    if announcement.encoded_len() > ANNOUNCEMENT_MAX_BYTES {
        return Err("announcement exceeds maximum size".to_string());
    }
    Ok((announcement, payload_hash))
}

fn preimage_bytes_from_message(message: &StrongNodeAnnouncementMessage) -> Result<Vec<u8>, ValidationError> {
    let static_id_raw = bytes_to_array_32(&message.static_id_raw).ok_or(ValidationError::Malformed)?;
    let pubkey_xonly = bytes_to_array_32(&message.pubkey_xonly).ok_or(ValidationError::Malformed)?;
    let preimage = AnnouncementPreimage {
        domain_tag: DOMAIN_TAG.to_vec(),
        schema_version: message.schema_version,
        network: message.network.clone(),
        static_id_raw,
        pubkey_xonly,
        seq_no: message.seq_no,
        window_start_ms: message.window_start_ms,
        window_end_ms: message.window_end_ms,
        found_blocks_10m: message.found_blocks10m,
        total_blocks_10m: message.total_blocks10m,
        sent_at_ms: message.sent_at_ms,
        claimed_ip: message.claimed_ip.clone(),
    };
    borsh::to_vec(&preimage).map_err(|_| ValidationError::Malformed)
}

fn sign_preimage(preimage: &[u8], secret_key: &SecretKey) -> Result<Vec<u8>, secp256k1::Error> {
    let digest = blake3::hash(preimage);
    let msg = SecpMessage::from_digest_slice(digest.as_bytes())?;
    let keypair = Keypair::from_secret_key(secp256k1::SECP256K1, secret_key);
    let sig: [u8; 64] = *keypair.sign_schnorr(msg).as_ref();
    Ok(sig.to_vec())
}

fn verify_signature(preimage: &[u8], pubkey_xonly: &[u8; 32], signature: &[u8]) -> Result<(), ValidationError> {
    let digest = blake3::hash(preimage);
    let msg = SecpMessage::from_digest_slice(digest.as_bytes()).map_err(|_| ValidationError::InvalidSignature)?;
    let pubkey = XOnlyPublicKey::from_slice(pubkey_xonly).map_err(|_| ValidationError::InvalidSignature)?;
    let signature = Signature::from_slice(signature).map_err(|_| ValidationError::InvalidSignature)?;
    signature.verify(&msg, &pubkey).map_err(|_| ValidationError::InvalidSignature)
}

fn allow_sender_rate(state: &mut EngineState, sender_ip: IpAddr, now_ms: u64) -> bool {
    let record = state.inbound_rate_by_sender.entry(sender_ip).or_default();
    if record.window_start_ms == 0 || now_ms.saturating_sub(record.window_start_ms) >= INBOUND_RATE_WINDOW_MS {
        record.window_start_ms = now_ms;
        record.msgs_in_window = 0;
    }
    record.msgs_in_window = record.msgs_in_window.saturating_add(1);
    record.last_seen_ms = now_ms;
    record.msgs_in_window <= INBOUND_RATE_MAX_MSGS_PER_WINDOW
}

fn allow_sender_new_id(
    state: &mut EngineState,
    sender_ip: IpAddr,
    static_id_raw: [u8; 32],
    now_ms: u64,
    window_ms: u64,
    max_new_ids: usize,
) -> bool {
    let record = state.inbound_new_ids_by_sender.entry(sender_ip).or_default();
    if record.window_start_ms == 0 || now_ms.saturating_sub(record.window_start_ms) >= window_ms {
        record.window_start_ms = now_ms;
        record.ids_in_window.clear();
    }
    record.last_seen_ms = now_ms;
    record.ids_in_window.insert(static_id_raw);
    record.ids_in_window.len() <= max_new_ids
}

fn trim_inbound_rate_cache(inbound_rate_by_sender: &mut BTreeMap<IpAddr, InboundRateRecord>, now_ms: u64) {
    inbound_rate_by_sender.retain(|_, record| now_ms.saturating_sub(record.last_seen_ms) <= 2 * INBOUND_RATE_WINDOW_MS);
    if inbound_rate_by_sender.len() <= INBOUND_RATE_MAX_TRACKED_SENDERS {
        return;
    }

    let overflow = inbound_rate_by_sender.len() - INBOUND_RATE_MAX_TRACKED_SENDERS;
    let mut by_age = inbound_rate_by_sender.iter().map(|(ip, record)| (*ip, record.last_seen_ms)).collect::<Vec<_>>();
    by_age.sort_by_key(|(_, last_seen)| *last_seen);
    for (ip, _) in by_age.into_iter().take(overflow) {
        inbound_rate_by_sender.remove(&ip);
    }
}

fn trim_inbound_new_ids_cache(inbound_new_ids_by_sender: &mut BTreeMap<IpAddr, InboundNewIdsRecord>, now_ms: u64) {
    inbound_new_ids_by_sender.retain(|_, record| now_ms.saturating_sub(record.last_seen_ms) <= 2 * INBOUND_NEW_IDS_WINDOW_MS);
    if inbound_new_ids_by_sender.len() <= INBOUND_NEW_IDS_MAX_TRACKED_SENDERS {
        return;
    }

    let overflow = inbound_new_ids_by_sender.len() - INBOUND_NEW_IDS_MAX_TRACKED_SENDERS;
    let mut by_age = inbound_new_ids_by_sender.iter().map(|(ip, record)| (*ip, record.last_seen_ms)).collect::<Vec<_>>();
    by_age.sort_by_key(|(_, last_seen)| *last_seen);
    for (ip, _) in by_age.into_iter().take(overflow) {
        inbound_new_ids_by_sender.remove(&ip);
    }
}

fn prune_samples(samples: &mut VecDeque<BlockSample>, now_ms: u64) {
    while let Some(front) = samples.front() {
        if now_ms.saturating_sub(front.now_ms) > ANNOUNCEMENT_WINDOW_MS {
            samples.pop_front();
        } else {
            break;
        }
    }
}

fn evict_stale_registry(registry: &mut BTreeMap<[u8; 32], RegistryEntry>, now_ms: u64) -> bool {
    let before = registry.len();
    registry.retain(|_, entry| now_ms.saturating_sub(entry.last_seen_ms) <= REGISTRY_TTL_MS);
    before != registry.len()
}

fn evict_registry_overflow(registry: &mut BTreeMap<[u8; 32], RegistryEntry>) {
    if registry.len() <= REGISTRY_CAP {
        return;
    }

    let overflow = registry.len() - REGISTRY_CAP;
    let mut candidates = registry
        .iter()
        .filter(|(_, entry)| entry.source != EntrySource::SelfNode)
        .map(|(static_id_raw, entry)| (*static_id_raw, entry.last_seen_ms))
        .collect::<Vec<_>>();
    candidates.sort_by(|(a_id, a_seen), (b_id, b_seen)| a_seen.cmp(b_seen).then_with(|| a_id.cmp(b_id)));
    for (static_id_raw, _) in candidates.into_iter().take(overflow) {
        registry.remove(&static_id_raw);
    }
}

fn load_or_create_identity(strong_nodes_dir: &Path) -> Result<NodeIdentity, String> {
    let path = strong_nodes_dir.join(NODE_IDENTITY_FILE);
    if path.exists() {
        let bytes = read_file_with_limit(&path, IDENTITY_FILE_MAX_BYTES)?;
        match serde_json::from_slice::<NodeIdentityDisk>(&bytes) {
            Ok(disk) => parse_identity_disk(disk),
            Err(err) => {
                quarantine_file(&path);
                warn!("strong-nodes: identity file was corrupted and moved to quarantine: {err}");
                create_and_persist_identity(strong_nodes_dir)
            }
        }
    } else {
        create_and_persist_identity(strong_nodes_dir)
    }
}

fn parse_identity_disk(disk: NodeIdentityDisk) -> Result<NodeIdentity, String> {
    if disk.schema_version != 1 {
        return Err(format!("unsupported node_identity schema version {}", disk.schema_version));
    }
    let secret_key_bytes = decode_hex_32(&disk.secret_key)?;
    let pubkey_xonly = decode_hex_32(&disk.public_key_xonly)?;
    let static_id_raw = decode_hex_32(&disk.static_id_raw)?;
    let secret_key = SecretKey::from_slice(&secret_key_bytes).map_err(|err| format!("invalid secret key: {err}"))?;
    let keypair = Keypair::from_secret_key(secp256k1::SECP256K1, &secret_key);
    let xonly = keypair.x_only_public_key().0.serialize();
    if pubkey_xonly != xonly {
        return Err("public key does not match secret key".to_string());
    }
    let expected_static_id = *blake3::hash(&pubkey_xonly).as_bytes();
    if static_id_raw != expected_static_id {
        return Err("static_id does not match pubkey hash".to_string());
    }
    Ok(NodeIdentity { secret_key, pubkey_xonly, static_id_raw, last_seq_no: disk.last_seq_no })
}

fn create_and_persist_identity(strong_nodes_dir: &Path) -> Result<NodeIdentity, String> {
    let mut rng = secp256k1::rand::thread_rng();
    let secret_key = SecretKey::new(&mut rng);
    let keypair = Keypair::from_secret_key(secp256k1::SECP256K1, &secret_key);
    let pubkey_xonly = keypair.x_only_public_key().0.serialize();
    let static_id_raw = *blake3::hash(&pubkey_xonly).as_bytes();
    let identity = NodeIdentity { secret_key, pubkey_xonly, static_id_raw, last_seq_no: 0 };
    persist_identity(strong_nodes_dir, &identity)?;
    Ok(identity)
}

fn persist_identity(strong_nodes_dir: &Path, identity: &NodeIdentity) -> Result<(), String> {
    let disk = NodeIdentityDisk {
        schema_version: 1,
        secret_key: hex_encode(identity.secret_key.secret_bytes()),
        public_key_xonly: hex_encode(identity.pubkey_xonly),
        static_id_raw: hex_encode(identity.static_id_raw),
        last_seq_no: identity.last_seq_no,
    };
    let bytes = serde_json::to_vec_pretty(&disk).map_err(|err| format!("failed serializing node identity: {err}"))?;
    write_atomic(strong_nodes_dir.join(NODE_IDENTITY_FILE), &bytes)?;
    set_private_file_permissions_if_supported(&strong_nodes_dir.join(NODE_IDENTITY_FILE));
    Ok(())
}

fn load_registry(strong_nodes_dir: &Path) -> Result<BTreeMap<[u8; 32], RegistryEntry>, String> {
    let path = strong_nodes_dir.join(REGISTRY_FILE);
    if !path.exists() {
        return Ok(BTreeMap::new());
    }

    let bytes = read_file_with_limit(&path, REGISTRY_FILE_MAX_BYTES)?;
    let disk = match serde_json::from_slice::<RegistryDisk>(&bytes) {
        Ok(disk) => disk,
        Err(err) => {
            quarantine_file(&path);
            return Err(format!("failed parsing registry json: {err}"));
        }
    };
    if disk.schema_version != 1 {
        return Err(format!("unsupported registry schema version {}", disk.schema_version));
    }

    let mut registry = BTreeMap::new();
    for entry in disk.entries {
        let static_id_raw = decode_hex_32(&entry.static_id_raw)?;
        let pubkey_xonly = decode_hex_32(&entry.pubkey_xonly)?;
        let payload_hash = decode_hex_32(&entry.payload_hash)?;
        let claimed_ip = entry.claimed_ip.as_deref().and_then(parse_claimed_ip_hex);
        let last_sender_ip = entry.last_sender_ip.as_deref().and_then(|s| s.parse::<IpAddr>().ok());
        let first_seen_ms = entry.first_seen_ms.unwrap_or(entry.last_seen_ms);
        registry.insert(
            static_id_raw,
            RegistryEntry {
                static_id_raw,
                pubkey_xonly,
                seq_no: entry.seq_no,
                window_start_ms: entry.window_start_ms,
                window_end_ms: entry.window_end_ms,
                found_blocks_10m: entry.found_blocks_10m,
                total_blocks_10m: entry.total_blocks_10m,
                sent_at_ms: entry.sent_at_ms,
                claimed_ip,
                last_sender_ip,
                source: EntrySource::from_str(&entry.source),
                signature_valid: entry.signature_valid,
                payload_hash,
                first_seen_ms,
                last_seen_ms: entry.last_seen_ms,
            },
        );
    }
    Ok(registry)
}

fn persist_registry(strong_nodes_dir: &Path, registry: &BTreeMap<[u8; 32], RegistryEntry>) -> Result<(), String> {
    let entries = registry
        .values()
        .map(|entry| RegistryEntryDisk {
            static_id_raw: hex_encode(entry.static_id_raw),
            pubkey_xonly: hex_encode(entry.pubkey_xonly),
            seq_no: entry.seq_no,
            window_start_ms: entry.window_start_ms,
            window_end_ms: entry.window_end_ms,
            found_blocks_10m: entry.found_blocks_10m,
            total_blocks_10m: entry.total_blocks_10m,
            sent_at_ms: entry.sent_at_ms,
            claimed_ip: entry.claimed_ip.map(|ip| hex_encode(canonicalize_claimed_ip(ip))),
            last_sender_ip: entry.last_sender_ip.map(|ip| ip.to_string()),
            source: entry.source.as_str().to_string(),
            signature_valid: entry.signature_valid,
            payload_hash: hex_encode(entry.payload_hash),
            first_seen_ms: Some(entry.first_seen_ms),
            last_seen_ms: entry.last_seen_ms,
        })
        .collect::<Vec<_>>();
    let disk = RegistryDisk { schema_version: 1, entries };
    let bytes = serde_json::to_vec_pretty(&disk).map_err(|err| format!("failed serializing registry: {err}"))?;
    write_atomic(strong_nodes_dir.join(REGISTRY_FILE), &bytes)
}

fn write_atomic(path: PathBuf, bytes: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    {
        let mut file = fs::File::create(&tmp).map_err(|err| format!("create tmp failed: {err}"))?;
        file.write_all(bytes).map_err(|err| format!("write tmp failed: {err}"))?;
        file.flush().map_err(|err| format!("flush tmp failed: {err}"))?;
        file.sync_all().map_err(|err| format!("sync tmp failed: {err}"))?;
    }
    fs::rename(&tmp, &path).map_err(|err| format!("rename tmp failed: {err}"))?;
    Ok(())
}

fn read_file_with_limit(path: &Path, max_bytes: usize) -> Result<Vec<u8>, String> {
    let metadata = fs::metadata(path).map_err(|err| format!("metadata failed: {err}"))?;
    if metadata.len() as usize > max_bytes {
        quarantine_file(path);
        return Err(format!("file too large (>{max_bytes} bytes): {}", path.display()));
    }
    fs::read(path).map_err(|err| format!("read failed: {err}"))
}

fn quarantine_file(path: &Path) {
    let ts = unix_now();
    let mut quarantine = path.to_path_buf();
    let new_ext = format!("quarantine.{ts}.json");
    quarantine.set_extension(new_ext);
    if let Err(err) = fs::rename(path, quarantine) {
        warn!("strong-nodes: failed to quarantine {}: {err}", path.display());
    }
}

fn decode_hex_32(value: &str) -> Result<[u8; 32], String> {
    let bytes = hex_decode(value).map_err(|err| format!("hex decode failed: {err}"))?;
    bytes_to_array_32(&bytes).ok_or_else(|| "expected 32-byte hex value".to_string())
}

fn bytes_to_array_32(bytes: &[u8]) -> Option<[u8; 32]> {
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Some(out)
}

fn parse_claimed_ip_bytes(bytes: &[u8]) -> Result<Option<IpAddr>, ()> {
    match bytes.len() {
        0 => Ok(None),
        4 => {
            let mut octets = [0u8; 4];
            octets.copy_from_slice(bytes);
            Ok(Some(IpAddr::V4(Ipv4Addr::from(octets))))
        }
        16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(bytes);
            let v6 = Ipv6Addr::from(octets);
            Ok(Some(match v6.to_ipv4() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(v6),
            }))
        }
        _ => Err(()),
    }
}

fn parse_claimed_ip_hex(value: &str) -> Option<IpAddr> {
    let raw = hex_decode(value).ok()?;
    parse_claimed_ip_bytes(&raw).ok().flatten()
}

fn canonicalize_claimed_ip(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => match v6.to_ipv4() {
            Some(v4) => v4.octets().to_vec(),
            None => v6.octets().to_vec(),
        },
    }
}

fn ip_to_canonical_string(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => match v6.to_ipv4() {
            Some(v4) => v4.to_string(),
            None => v6.to_string(),
        },
    }
}

#[cfg(unix)]
fn set_private_file_permissions_if_supported(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(metadata) = fs::metadata(path) {
        let mut perms = metadata.permissions();
        perms.set_mode(0o600);
        let _ = fs::set_permissions(path, perms);
    }
}

#[cfg(not(unix))]
fn set_private_file_permissions_if_supported(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_dir(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("strong-nodes-test-{name}-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn build_announcement_for_test(
        identity: &NodeIdentity,
        network: &str,
        seq_no: u64,
        found_blocks_10m: u32,
        total_blocks_10m: u32,
        sent_at_ms: u64,
        claimed_ip: Option<IpAddr>,
    ) -> StrongNodeAnnouncementMessage {
        let mut message = StrongNodeAnnouncementMessage {
            schema_version: ANNOUNCEMENT_SCHEMA_VERSION,
            network: network.to_string(),
            static_id_raw: identity.static_id_raw.to_vec(),
            pubkey_xonly: identity.pubkey_xonly.to_vec(),
            seq_no,
            window_start_ms: sent_at_ms.saturating_sub(ANNOUNCEMENT_WINDOW_MS / 2),
            window_end_ms: sent_at_ms,
            found_blocks10m: found_blocks_10m,
            total_blocks10m: total_blocks_10m,
            sent_at_ms,
            claimed_ip: claimed_ip.map(canonicalize_claimed_ip).unwrap_or_default(),
            signature: Vec::new(),
        };
        let preimage = preimage_bytes_from_message(&message).unwrap();
        message.signature = sign_preimage(&preimage, &identity.secret_key).unwrap();
        message
    }

    #[test]
    fn static_id_hex_roundtrip_is_consistent() {
        let dir = temp_dir("static-id");
        let identity = create_and_persist_identity(&dir).unwrap();
        let encoded = hex_encode(identity.static_id_raw);
        let decoded = decode_hex_32(&encoded).unwrap();
        assert_eq!(decoded, identity.static_id_raw);
    }

    #[test]
    fn signature_preimage_is_deterministic() {
        let dir = temp_dir("signature");
        let identity = create_and_persist_identity(&dir).unwrap();
        let stats = WindowStats { found: 12, total: 100, window_start_ms: 1, window_end_ms: 2 };
        let (a1, _) = build_signed_announcement(&identity, "mainnet", Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))), stats).unwrap();
        let pre1 = preimage_bytes_from_message(&a1).unwrap();
        let pre2 = preimage_bytes_from_message(&a1).unwrap();
        assert_eq!(pre1, pre2);
    }

    #[test]
    fn claimed_ip_parsing_and_canonicalization_supports_ipv4_mapped_ipv6() {
        let raw_v4 = vec![127, 0, 0, 1];
        let parsed_v4 = parse_claimed_ip_bytes(&raw_v4).unwrap().unwrap();
        assert_eq!(parsed_v4, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

        let mapped = Ipv4Addr::new(10, 0, 0, 9).to_ipv6_mapped().octets().to_vec();
        let parsed = parse_claimed_ip_bytes(&mapped).unwrap().unwrap();
        assert_eq!(parsed, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)));
        assert_eq!(canonicalize_claimed_ip(parsed), vec![10, 0, 0, 9]);
    }

    #[test]
    fn inbound_new_id_cap_limits_unique_ids_per_sender_window() {
        let sender = IpAddr::V4(Ipv4Addr::new(5, 5, 5, 5));
        let mut state = EngineState::default();
        let now_ms = unix_now();

        for i in 0..INBOUND_NEW_IDS_MAX_PER_WINDOW {
            let mut static_id_raw = [0u8; 32];
            static_id_raw[0] = i as u8;
            assert!(allow_sender_new_id(
                &mut state,
                sender,
                static_id_raw,
                now_ms,
                INBOUND_NEW_IDS_WINDOW_MS,
                INBOUND_NEW_IDS_MAX_PER_WINDOW
            ));
        }

        let mut overflow_static_id_raw = [0u8; 32];
        overflow_static_id_raw[0] = 250;
        overflow_static_id_raw[1] = 1;
        assert!(!allow_sender_new_id(
            &mut state,
            sender,
            overflow_static_id_raw,
            now_ms,
            INBOUND_NEW_IDS_WINDOW_MS,
            INBOUND_NEW_IDS_MAX_PER_WINDOW
        ));
    }

    #[test]
    fn seq_conflict_and_dedup_for_same_seq_are_handled() {
        let dir = temp_dir("seq-conflict");
        let engine =
            StrongNodesEngine::new(StrongNodesEngineConfig { enabled: true, network: "simnet".to_string(), app_data_dir: dir });
        let remote_identity_dir = temp_dir("seq-conflict-remote");
        let remote_identity = create_and_persist_identity(&remote_identity_dir).unwrap();
        let sent_at_ms = unix_now();

        let first = build_announcement_for_test(&remote_identity, "simnet", 5, 30, 100, sent_at_ms, None);
        let first_outcome = engine.ingest_announcement(&first, IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)), true);
        assert!(matches!(first_outcome, IngestOutcome::Accepted));

        let dedup_outcome = engine.ingest_announcement(&first, IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)), true);
        assert!(matches!(dedup_outcome, IngestOutcome::Dropped));

        let conflict = build_announcement_for_test(&remote_identity, "simnet", 5, 31, 100, sent_at_ms.saturating_add(1), None);
        let conflict_outcome = engine.ingest_announcement(&conflict, IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)), true);
        assert!(matches!(conflict_outcome, IngestOutcome::Strike { .. }));

        let snapshot = engine.snapshot(true);
        assert_eq!(snapshot.seq_conflict_total, 1);
    }

    #[test]
    fn flush_policy_honors_debounce_and_hard_flush() {
        let mut state = EngineState::default();
        state.dirty = true;
        state.dirty_since_ms = Some(1_000);
        state.last_flush_ms = 1_000;
        let dir = temp_dir("flush");
        maybe_flush_registry_locked(&dir, &mut state, 10_000).unwrap();
        assert!(state.dirty);
        maybe_flush_registry_locked(&dir, &mut state, 31_001).unwrap();
        assert!(!state.dirty);

        state.dirty = true;
        state.dirty_since_ms = Some(100_000);
        state.last_flush_ms = 1_000;
        maybe_flush_registry_locked(&dir, &mut state, 61_001).unwrap();
        assert!(!state.dirty);
    }

    #[test]
    fn circuit_breaker_counts_only_internal_errors() {
        let dir = temp_dir("circuit");
        let engine =
            StrongNodesEngine::new(StrongNodesEngineConfig { enabled: true, network: "mainnet".to_string(), app_data_dir: dir });
        let now = unix_now();
        for _ in 0..(INTERNAL_ERROR_THRESHOLD * 2) {
            let invalid = StrongNodeAnnouncementMessage {
                schema_version: ANNOUNCEMENT_SCHEMA_VERSION,
                network: "mainnet".to_string(),
                static_id_raw: vec![1, 2, 3],
                pubkey_xonly: vec![4, 5, 6],
                seq_no: 1,
                window_start_ms: now.saturating_sub(1000),
                window_end_ms: now,
                found_blocks10m: 1,
                total_blocks10m: 1,
                sent_at_ms: now,
                claimed_ip: vec![],
                signature: vec![0u8; 64],
            };
            let _ = engine.ingest_announcement(&invalid, IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), true);
        }
        {
            let state = engine.state.lock();
            assert_eq!(state.disabled_reason_code, None);
        }

        let mut state = engine.state.lock();
        for i in 0..INTERNAL_ERROR_THRESHOLD {
            engine.record_internal_error_locked(&mut state, format!("err-{i}"), now.saturating_add(i as u64));
        }
        assert_eq!(state.disabled_reason_code, Some(DisabledReasonCode::CircuitBreakerOpen));
    }
}
