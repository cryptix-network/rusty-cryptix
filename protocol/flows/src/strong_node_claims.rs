use crate::node_identity::{network_code_from_name, UnifiedNodeIdentity};
use cryptix_consensus_core::ChainPath;
use cryptix_core::{time::unix_now, warn};
use cryptix_hashes::Hash;
use cryptix_p2p_lib::pb::BlockProducerClaimV1Message;
use hex::{decode as hex_decode, encode as hex_encode};
use parking_lot::Mutex;
use secp256k1::{schnorr::Signature as SchnorrSignature, Keypair, Message as SecpMessage, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const STRONG_NODE_CLAIMS_P2P_SERVICE_BIT: u64 = 1 << 22;
pub const CLAIM_WINDOW_SIZE_BLOCKS: usize = 1000;
pub const CLAIM_REORG_MARGIN_BLOCKS: usize = 256;
pub const PENDING_UNKNOWN_CLAIMS_CAP: usize = 4096;
pub const PENDING_UNKNOWN_CLAIMS_TTL_SECONDS: u64 = 180;

const CLAIM_SCHEMA_VERSION: u32 = 1;
const CLAIM_DOMAIN_TAG: &[u8] = b"cryptix-block-claim-v1";
const CLAIM_STATE_SCHEMA_VERSION: u32 = 1;
const CLAIMS_DIR: &str = "strong-node-claims";
const CLAIMS_STATE_CURRENT_FILE: &str = "current.snapshot";
const CLAIMS_STATE_PREVIOUS_FILE: &str = "previous.snapshot";

#[derive(Clone, Debug)]
pub enum ClaimIngestOutcome {
    Ignored,
    Dropped,
    Accepted { pending: bool },
    Strike { reason: String, node_id: Option<[u8; 32]> },
}

#[derive(Clone, Debug)]
pub struct StrongNodeClaimEntrySnapshot {
    pub node_id: String,
    pub public_key_xonly: String,
    pub claimed_blocks: u32,
    pub share_bps: u32,
    pub last_claim_block_hash: Option<String>,
    pub last_claim_time_ms: u64,
}

#[derive(Clone, Debug)]
pub struct StrongNodeClaimsRuntimeSnapshot {
    pub enabled: bool,
    pub hardfork_active: bool,
    pub runtime_available: bool,
    pub window_size: u32,
    pub conflict_total: u64,
    pub entries: Vec<StrongNodeClaimEntrySnapshot>,
}

#[derive(Clone, Debug)]
struct ClaimRecord {
    block_hash: Hash,
    node_id: [u8; 32],
    pubkey_xonly: [u8; 32],
    signature: [u8; 64],
    claim_id: [u8; 32],
    received_at_ms: u64,
}

#[derive(Default)]
struct EngineState {
    last_sink: Option<Hash>,
    window_hashes: VecDeque<Hash>,
    window_set: HashSet<Hash>,
    retention_hashes: VecDeque<Hash>,
    retention_set: HashSet<Hash>,
    recent_claims_by_block: HashMap<Hash, BTreeMap<[u8; 32], ClaimRecord>>,
    pending_unknown_claims: HashMap<Hash, Vec<ClaimRecord>>,
    winning_claim_by_block: HashMap<Hash, ClaimRecord>,
    score_by_node_id: BTreeMap<[u8; 32], u32>,
    last_claim_time_by_node_id: BTreeMap<[u8; 32], u64>,
    last_claim_block_by_node_id: BTreeMap<[u8; 32], Hash>,
    conflict_total: u64,
    dirty: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ClaimStateDisk {
    schema_version: u32,
    #[serde(default)]
    last_sink: Option<String>,
    #[serde(default)]
    window_hashes: Vec<String>,
    #[serde(default)]
    retention_hashes: Vec<String>,
    #[serde(default)]
    winners: Vec<ClaimDiskRecord>,
    #[serde(default)]
    conflict_total: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ClaimDiskRecord {
    block_hash: String,
    node_id: String,
    pubkey_xonly: String,
    signature: String,
    claim_id: String,
    received_at_ms: u64,
}

pub struct StrongNodeClaimsEngine {
    enabled: bool,
    network_code: u8,
    claims_dir: PathBuf,
    state: Mutex<EngineState>,
}

impl StrongNodeClaimsEngine {
    pub fn new(enabled: bool, network_name: &str, app_data_dir: &Path) -> Self {
        let network_code = network_code_from_name(network_name).unwrap_or(0);
        let claims_dir = app_data_dir.join(CLAIMS_DIR);
        if enabled {
            let _ = fs::create_dir_all(&claims_dir);
        }

        let mut state = EngineState::default();
        if enabled {
            if let Err(err) = load_state(&claims_dir, &mut state) {
                warn!("strong-node-claims: failed loading persisted state: {err}");
            }
            recompute_scores(&mut state);
        }

        Self { enabled, network_code, claims_dir, state: Mutex::new(state) }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn should_advertise_service_bit(&self, hardfork_active: bool) -> bool {
        self.enabled && hardfork_active
    }

    pub fn build_local_claim(&self, block_hash: Hash, identity: &UnifiedNodeIdentity) -> Result<BlockProducerClaimV1Message, String> {
        let node_id = identity.node_id;
        let claim_id = compute_claim_id(self.network_code, &block_hash, &node_id);
        let message = SecpMessage::from_digest_slice(&claim_id).map_err(|err| format!("invalid claim digest: {err}"))?;
        let keypair = Keypair::from_secret_key(secp256k1::SECP256K1, &identity.secret_key);
        let signature = *keypair.sign_schnorr(message).as_ref();
        Ok(BlockProducerClaimV1Message {
            schema_version: CLAIM_SCHEMA_VERSION,
            network: self.network_code as u32,
            block_hash: block_hash.as_bytes().to_vec(),
            node_pubkey_xonly: identity.pubkey_xonly.to_vec(),
            signature: signature.to_vec(),
        })
    }

    pub fn ingest_claim(&self, message: &BlockProducerClaimV1Message, hardfork_active: bool) -> ClaimIngestOutcome {
        if !self.enabled || !hardfork_active {
            return ClaimIngestOutcome::Ignored;
        }
        let now_ms = unix_now();
        let record = match validate_claim_message(message, self.network_code, now_ms) {
            Ok(record) => record,
            Err(reason) => {
                return ClaimIngestOutcome::Strike { reason, node_id: None };
            }
        };

        let mut state = self.state.lock();
        cleanup_pending_unknown_claims(&mut state, now_ms);
        let known_block = state.retention_set.contains(&record.block_hash) || state.window_set.contains(&record.block_hash);
        if !known_block {
            enqueue_pending_unknown_claim(&mut state, record, now_ms);
            state.dirty = true;
            return ClaimIngestOutcome::Accepted { pending: true };
        }

        let accepted = insert_known_claim_locked(&mut state, record);
        if accepted {
            state.dirty = true;
            ClaimIngestOutcome::Accepted { pending: false }
        } else {
            ClaimIngestOutcome::Dropped
        }
    }

    pub fn apply_chain_path_update(&self, chain_path: ChainPath, new_sink: Hash, hardfork_active: bool) {
        if !self.enabled || !hardfork_active {
            return;
        }
        let now_ms = unix_now();
        let mut state = self.state.lock();
        for hash in chain_path.removed {
            if state.window_set.remove(&hash) {
                state.window_hashes.retain(|entry| *entry != hash);
                if let Some(winner_node_id) = state.winning_claim_by_block.get(&hash).map(|winner| winner.node_id) {
                    decrement_score(&mut state.score_by_node_id, winner_node_id);
                }
                state.dirty = true;
            }
            if state.retention_set.remove(&hash) {
                state.retention_hashes.retain(|entry| *entry != hash);
                state.dirty = true;
            }
            if purge_block_claim_state_locked(&mut state, hash) {
                state.dirty = true;
            }
        }

        for hash in chain_path.added {
            if state.retention_set.insert(hash) {
                state.retention_hashes.push_back(hash);
                state.dirty = true;
            }
            if state.window_set.insert(hash) {
                state.window_hashes.push_back(hash);
                if let Some(winner_node_id) = state.winning_claim_by_block.get(&hash).map(|winner| winner.node_id) {
                    increment_score(&mut state.score_by_node_id, winner_node_id);
                }
                state.dirty = true;
            }
            promote_pending_unknown_claims_for_block_locked(&mut state, hash);
        }

        while state.window_hashes.len() > CLAIM_WINDOW_SIZE_BLOCKS {
            if let Some(evicted) = state.window_hashes.pop_front() {
                state.window_set.remove(&evicted);
                if let Some(winner_node_id) = state.winning_claim_by_block.get(&evicted).map(|winner| winner.node_id) {
                    decrement_score(&mut state.score_by_node_id, winner_node_id);
                }
                state.dirty = true;
            }
        }

        while state.retention_hashes.len() > CLAIM_WINDOW_SIZE_BLOCKS + CLAIM_REORG_MARGIN_BLOCKS {
            if let Some(evicted) = state.retention_hashes.pop_front() {
                state.retention_set.remove(&evicted);
                let _ = purge_block_claim_state_locked(&mut state, evicted);
                state.dirty = true;
            }
        }

        cleanup_pending_unknown_claims(&mut state, now_ms);
        state.last_sink = Some(new_sink);
    }

    pub fn last_sink(&self) -> Option<Hash> {
        self.state.lock().last_sink
    }

    pub fn snapshot(&self, hardfork_active: bool) -> StrongNodeClaimsRuntimeSnapshot {
        let state = self.state.lock();
        let mut entries = state
            .score_by_node_id
            .iter()
            .map(|(node_id, score)| {
                let public_key_xonly = state
                    .winning_claim_by_block
                    .values()
                    .find(|claim| &claim.node_id == node_id)
                    .map(|claim| hex_encode(claim.pubkey_xonly))
                    .unwrap_or_default();
                let share_bps = if CLAIM_WINDOW_SIZE_BLOCKS == 0 {
                    0
                } else {
                    (((*score as u64) * 10_000) / CLAIM_WINDOW_SIZE_BLOCKS as u64) as u32
                };
                StrongNodeClaimEntrySnapshot {
                    node_id: hex_encode(node_id),
                    public_key_xonly,
                    claimed_blocks: *score,
                    share_bps,
                    last_claim_block_hash: state.last_claim_block_by_node_id.get(node_id).map(|hash| hash.to_string()),
                    last_claim_time_ms: *state.last_claim_time_by_node_id.get(node_id).unwrap_or(&0),
                }
            })
            .collect::<Vec<_>>();
        entries.sort_by(|a, b| b.claimed_blocks.cmp(&a.claimed_blocks).then_with(|| a.node_id.cmp(&b.node_id)));
        StrongNodeClaimsRuntimeSnapshot {
            enabled: self.enabled,
            hardfork_active,
            runtime_available: self.enabled && hardfork_active,
            window_size: CLAIM_WINDOW_SIZE_BLOCKS as u32,
            conflict_total: state.conflict_total,
            entries,
        }
    }

    pub fn best_effort_flush(&self) {
        let mut state = self.state.lock();
        let _ = persist_state_if_dirty(&self.claims_dir, &mut state);
    }

    pub fn maybe_flush(&self) {
        let mut state = self.state.lock();
        let _ = persist_state_if_dirty(&self.claims_dir, &mut state);
    }
}

fn validate_claim_message(
    message: &BlockProducerClaimV1Message,
    expected_network_code: u8,
    now_ms: u64,
) -> Result<ClaimRecord, String> {
    if message.schema_version != CLAIM_SCHEMA_VERSION {
        return Err(format!("invalid claim schema version {}", message.schema_version));
    }
    if message.network != expected_network_code as u32 {
        return Err("claim network mismatch".to_string());
    }
    let block_hash_raw: [u8; 32] =
        message.block_hash.as_slice().try_into().map_err(|_| "block_hash must be exactly 32 bytes".to_string())?;
    let pubkey_xonly: [u8; 32] =
        message.node_pubkey_xonly.as_slice().try_into().map_err(|_| "node_pubkey_xonly must be exactly 32 bytes".to_string())?;
    let signature: [u8; 64] = message.signature.as_slice().try_into().map_err(|_| "signature must be exactly 64 bytes".to_string())?;

    let node_id = *blake3::hash(&pubkey_xonly).as_bytes();
    let block_hash = Hash::from_bytes(block_hash_raw);
    let claim_id = compute_claim_id(expected_network_code, &block_hash, &node_id);
    let secp_message = SecpMessage::from_digest_slice(&claim_id).map_err(|err| format!("invalid claim digest: {err}"))?;
    let pubkey = XOnlyPublicKey::from_slice(&pubkey_xonly).map_err(|_| "invalid x-only pubkey".to_string())?;
    let signature = SchnorrSignature::from_slice(&signature).map_err(|_| "invalid schnorr signature bytes".to_string())?;
    signature.verify(&secp_message, &pubkey).map_err(|_| "claim signature verification failed".to_string())?;

    Ok(ClaimRecord { block_hash, node_id, pubkey_xonly, signature: *signature.as_ref(), claim_id, received_at_ms: now_ms })
}

fn compute_claim_id(network_code: u8, block_hash: &Hash, node_id: &[u8; 32]) -> [u8; 32] {
    let mut payload = Vec::with_capacity(CLAIM_DOMAIN_TAG.len() + 1 + 32 + 32);
    payload.extend_from_slice(CLAIM_DOMAIN_TAG);
    payload.push(network_code);
    payload.extend_from_slice(&block_hash.as_bytes());
    payload.extend_from_slice(node_id);
    *blake3::hash(&payload).as_bytes()
}

fn insert_known_claim_locked(state: &mut EngineState, record: ClaimRecord) -> bool {
    let block_hash = record.block_hash;
    let entry = state.recent_claims_by_block.entry(block_hash).or_default();
    if entry.contains_key(&record.node_id) {
        return false;
    }
    entry.insert(record.node_id, record.clone());
    if entry.len() > 1 {
        state.conflict_total = state.conflict_total.saturating_add(1);
    }

    let new_winner = entry.iter().next().map(|(_, value)| value.clone());
    let old_winner = state.winning_claim_by_block.insert(block_hash, new_winner.clone().expect("winner exists"));
    if state.window_set.contains(&block_hash) {
        if let Some(old) = old_winner {
            decrement_score(&mut state.score_by_node_id, old.node_id);
        }
        increment_score(&mut state.score_by_node_id, new_winner.as_ref().unwrap().node_id);
    }
    if let Some(winner) = new_winner {
        state.last_claim_time_by_node_id.insert(winner.node_id, winner.received_at_ms);
        state.last_claim_block_by_node_id.insert(winner.node_id, winner.block_hash);
    }
    true
}

fn enqueue_pending_unknown_claim(state: &mut EngineState, record: ClaimRecord, now_ms: u64) {
    let list = state.pending_unknown_claims.entry(record.block_hash).or_default();
    if list.iter().any(|existing| existing.node_id == record.node_id) {
        return;
    }
    list.push(record);
    cleanup_pending_unknown_claims(state, now_ms);
}

fn promote_pending_unknown_claims_for_block_locked(state: &mut EngineState, block_hash: Hash) {
    if let Some(mut pending) = state.pending_unknown_claims.remove(&block_hash) {
        pending.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        for claim in pending {
            let _ = insert_known_claim_locked(state, claim);
        }
    }
}

fn cleanup_pending_unknown_claims(state: &mut EngineState, now_ms: u64) {
    let ttl_ms = PENDING_UNKNOWN_CLAIMS_TTL_SECONDS * 1000;
    state.pending_unknown_claims.retain(|_, claims| {
        claims.retain(|claim| now_ms.saturating_sub(claim.received_at_ms) <= ttl_ms);
        !claims.is_empty()
    });

    while pending_claims_count(state) > PENDING_UNKNOWN_CLAIMS_CAP {
        let oldest_block = state
            .pending_unknown_claims
            .iter()
            .filter_map(|(hash, claims)| claims.first().map(|claim| (*hash, claim.received_at_ms)))
            .min_by_key(|(_, ts)| *ts)
            .map(|(hash, _)| hash);
        let Some(oldest_block) = oldest_block else {
            break;
        };
        if let Some(claims) = state.pending_unknown_claims.get_mut(&oldest_block) {
            if !claims.is_empty() {
                claims.remove(0);
            }
            if claims.is_empty() {
                state.pending_unknown_claims.remove(&oldest_block);
            }
        }
    }
}

fn pending_claims_count(state: &EngineState) -> usize {
    state.pending_unknown_claims.values().map(|claims| claims.len()).sum()
}

fn increment_score(score: &mut BTreeMap<[u8; 32], u32>, node_id: [u8; 32]) {
    let entry = score.entry(node_id).or_default();
    *entry = entry.saturating_add(1);
}

fn decrement_score(score: &mut BTreeMap<[u8; 32], u32>, node_id: [u8; 32]) {
    if let Some(entry) = score.get_mut(&node_id) {
        *entry = entry.saturating_sub(1);
        if *entry == 0 {
            score.remove(&node_id);
        }
    }
}

fn purge_block_claim_state_locked(state: &mut EngineState, block_hash: Hash) -> bool {
    let mut changed = false;
    if state.recent_claims_by_block.remove(&block_hash).is_some() {
        changed = true;
    }
    if state.winning_claim_by_block.remove(&block_hash).is_some() {
        changed = true;
    }
    if state.pending_unknown_claims.remove(&block_hash).is_some() {
        changed = true;
    }
    changed
}

fn recompute_scores(state: &mut EngineState) {
    state.score_by_node_id.clear();
    state.last_claim_block_by_node_id.clear();
    state.last_claim_time_by_node_id.clear();
    for hash in state.window_hashes.iter().copied() {
        if let Some((node_id, received_at_ms, block_hash)) =
            state.winning_claim_by_block.get(&hash).map(|winner| (winner.node_id, winner.received_at_ms, winner.block_hash))
        {
            increment_score(&mut state.score_by_node_id, node_id);
            state.last_claim_time_by_node_id.insert(node_id, received_at_ms);
            state.last_claim_block_by_node_id.insert(node_id, block_hash);
        }
    }
}

fn load_state(claims_dir: &Path, state: &mut EngineState) -> Result<(), String> {
    let current_path = claims_dir.join(CLAIMS_STATE_CURRENT_FILE);
    let previous_path = claims_dir.join(CLAIMS_STATE_PREVIOUS_FILE);
    let disk = match read_and_decode_state_file(&current_path) {
        Ok(Some(disk)) => disk,
        Err(err) => {
            warn!("strong-node-claims: current snapshot invalid ({}), quarantining {}", err, current_path.display());
            let _ = quarantine_state_file(&current_path);
            read_and_decode_state_file(&previous_path)
                .map_err(|fallback_err| format!("failed decoding fallback previous claim state: {fallback_err}"))?
                .ok_or_else(|| "no valid claim snapshot found after current snapshot decode failure".to_string())?
        }
        Ok(None) => match read_and_decode_state_file(&previous_path) {
            Ok(Some(disk)) => disk,
            Ok(None) => return Ok(()),
            Err(err) => return Err(format!("failed decoding fallback previous claim state: {err}")),
        },
    };
    if disk.schema_version != CLAIM_STATE_SCHEMA_VERSION {
        return Err(format!("unsupported claim state schema version {}", disk.schema_version));
    }
    state.last_sink = disk
        .last_sink
        .as_deref()
        .map(decode_hash_hex)
        .transpose()
        .map_err(|err| format!("invalid persisted last sink hash: {err}"))?;
    state.window_hashes.clear();
    state.window_set.clear();
    state.retention_hashes.clear();
    state.retention_set.clear();
    state.recent_claims_by_block.clear();
    state.winning_claim_by_block.clear();
    state.pending_unknown_claims.clear();
    state.score_by_node_id.clear();
    state.last_claim_time_by_node_id.clear();
    state.last_claim_block_by_node_id.clear();
    state.conflict_total = disk.conflict_total;

    for hash_hex in disk.window_hashes {
        let hash = decode_hash_hex(&hash_hex).map_err(|err| format!("invalid persisted window hash: {err}"))?;
        if state.window_set.insert(hash) {
            state.window_hashes.push_back(hash);
        }
    }
    for hash_hex in disk.retention_hashes {
        let hash = decode_hash_hex(&hash_hex).map_err(|err| format!("invalid persisted retention hash: {err}"))?;
        if state.retention_set.insert(hash) {
            state.retention_hashes.push_back(hash);
        }
    }
    for winner in disk.winners {
        let block_hash = decode_hash_hex(&winner.block_hash).map_err(|err| format!("invalid winner block hash: {err}"))?;
        let node_id = decode_hex_32(&winner.node_id)?;
        let pubkey_xonly = decode_hex_32(&winner.pubkey_xonly)?;
        let signature = decode_hex_64(&winner.signature)?;
        let claim_id = decode_hex_32(&winner.claim_id)?;
        let record = ClaimRecord { block_hash, node_id, pubkey_xonly, signature, claim_id, received_at_ms: winner.received_at_ms };
        state.winning_claim_by_block.insert(block_hash, record.clone());
        state.recent_claims_by_block.entry(block_hash).or_default().insert(node_id, record);
    }
    recompute_scores(state);
    Ok(())
}

fn read_and_decode_state_file(path: &Path) -> Result<Option<ClaimStateDisk>, String> {
    let data = match fs::read(path) {
        Ok(data) => data,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(format!("failed reading {}: {err}", path.display())),
    };
    let disk: ClaimStateDisk = serde_json::from_slice(&data).map_err(|err| format!("failed decoding {}: {err}", path.display()))?;
    Ok(Some(disk))
}

fn quarantine_state_file(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    let quarantine = path.with_extension(format!(
        "corrupt-{}",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|duration| duration.as_millis()).unwrap_or(0)
    ));
    fs::rename(path, &quarantine).map_err(|err| format!("failed quarantining {} to {}: {err}", path.display(), quarantine.display()))
}

fn persist_state_if_dirty(claims_dir: &Path, state: &mut EngineState) -> Result<(), String> {
    if !state.dirty {
        return Ok(());
    }
    let disk = ClaimStateDisk {
        schema_version: CLAIM_STATE_SCHEMA_VERSION,
        last_sink: state.last_sink.map(|hash| hash.to_string()),
        window_hashes: state.window_hashes.iter().map(|hash| hash.to_string()).collect(),
        retention_hashes: state.retention_hashes.iter().map(|hash| hash.to_string()).collect(),
        winners: state
            .winning_claim_by_block
            .values()
            .map(|winner| ClaimDiskRecord {
                block_hash: winner.block_hash.to_string(),
                node_id: hex_encode(winner.node_id),
                pubkey_xonly: hex_encode(winner.pubkey_xonly),
                signature: hex_encode(winner.signature),
                claim_id: hex_encode(winner.claim_id),
                received_at_ms: winner.received_at_ms,
            })
            .collect(),
        conflict_total: state.conflict_total,
    };
    persist_disk_state(claims_dir, &disk)?;
    state.dirty = false;
    Ok(())
}

fn persist_disk_state(claims_dir: &Path, disk: &ClaimStateDisk) -> Result<(), String> {
    fs::create_dir_all(claims_dir).map_err(|err| format!("failed creating claim state dir: {err}"))?;
    let current_path = claims_dir.join(CLAIMS_STATE_CURRENT_FILE);
    let previous_path = claims_dir.join(CLAIMS_STATE_PREVIOUS_FILE);
    let tmp_path = claims_dir.join(format!("{CLAIMS_STATE_CURRENT_FILE}.tmp"));

    let mut bytes = serde_json::to_vec_pretty(disk).map_err(|err| format!("failed serializing claim state: {err}"))?;
    bytes.push(b'\n');

    {
        let mut file = File::create(&tmp_path).map_err(|err| format!("failed creating temp claim state: {err}"))?;
        file.write_all(&bytes).map_err(|err| format!("failed writing temp claim state: {err}"))?;
        file.sync_all().map_err(|err| format!("failed syncing temp claim state: {err}"))?;
    }

    if current_path.exists() {
        let _ = fs::copy(&current_path, &previous_path);
    }
    fs::rename(&tmp_path, &current_path).map_err(|err| format!("failed replacing claim state: {err}"))?;
    Ok(())
}

fn decode_hex_32(value: &str) -> Result<[u8; 32], String> {
    let decoded = hex_decode(value.trim()).map_err(|err| format!("invalid hex value: {err}"))?;
    decoded.as_slice().try_into().map_err(|_| "expected 32-byte hex value".to_string())
}

fn decode_hex_64(value: &str) -> Result<[u8; 64], String> {
    let decoded = hex_decode(value.trim()).map_err(|err| format!("invalid hex value: {err}"))?;
    decoded.as_slice().try_into().map_err(|_| "expected 64-byte hex value".to_string())
}

fn decode_hash_hex(value: &str) -> Result<Hash, String> {
    let raw = decode_hex_32(value)?;
    Ok(Hash::from_bytes(raw))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[derive(Debug, Deserialize)]
    struct ClaimVector {
        name: String,
        network_u8: u8,
        block_hash_hex: String,
        pubkey_xonly_hex: String,
        node_id_hex: String,
        claim_digest_hex: String,
        signature_hex: String,
    }

    #[test]
    fn locked_constants_match_rev3() {
        assert_eq!(CLAIM_WINDOW_SIZE_BLOCKS, 1000);
        assert_eq!(CLAIM_REORG_MARGIN_BLOCKS, 256);
        assert_eq!(PENDING_UNKNOWN_CLAIMS_CAP, 4096);
        assert_eq!(PENDING_UNKNOWN_CLAIMS_TTL_SECONDS, 180);
    }

    #[test]
    fn cross_language_vectors_match() {
        let vectors_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("docs")
            .join("strong_node_claimant_hf_v1_1_vectors.json");
        let raw = std::fs::read(&vectors_path).expect("failed reading vector file");
        let vectors: Vec<ClaimVector> = serde_json::from_slice(&raw).expect("failed decoding vector file");
        assert!(vectors.len() >= 5, "expected at least 5 vectors");

        for vector in vectors {
            let block_hash_raw = decode_hex_32(&vector.block_hash_hex).expect("invalid block_hash_hex");
            let pubkey_xonly = decode_hex_32(&vector.pubkey_xonly_hex).expect("invalid pubkey_xonly_hex");
            let expected_node_id = decode_hex_32(&vector.node_id_hex).expect("invalid node_id_hex");
            let expected_claim_digest = decode_hex_32(&vector.claim_digest_hex).expect("invalid claim_digest_hex");
            let signature = decode_hex_64(&vector.signature_hex).expect("invalid signature_hex");

            let node_id = *blake3::hash(&pubkey_xonly).as_bytes();
            assert_eq!(node_id, expected_node_id, "{}: node_id mismatch", vector.name);

            let claim_digest = compute_claim_id(vector.network_u8, &Hash::from_bytes(block_hash_raw), &node_id);
            assert_eq!(claim_digest, expected_claim_digest, "{}: claim_digest mismatch", vector.name);

            let secp_message = SecpMessage::from_digest_slice(&claim_digest).expect("invalid claim digest");
            let pubkey = XOnlyPublicKey::from_slice(&pubkey_xonly).expect("invalid pubkey");
            let signature = SchnorrSignature::from_slice(&signature).expect("invalid signature");
            signature.verify(&secp_message, &pubkey).expect("signature verification failed");
        }
    }

    #[test]
    fn pending_claim_promotion_and_restart_rebuild() {
        let temp_dir = std::env::temp_dir().join(format!("strong-node-claims-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).expect("failed creating temp dir");
        let engine = StrongNodeClaimsEngine::new(true, "mainnet", &temp_dir);

        let claim = build_signed_claim_message(
            0,
            "9e335f14f1a549c374a273b014e4e6658c666b9be6bb7478085510abcba7fae2",
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        );
        let outcome = engine.ingest_claim(&claim, true);
        match outcome {
            ClaimIngestOutcome::Accepted { pending } => assert!(pending, "claim should be pending before block is known"),
            other => panic!("unexpected ingest outcome: {other:?}"),
        }
        assert!(engine.snapshot(true).entries.is_empty(), "pending claim should not impact score before promotion");

        let block_hash = Hash::from_bytes(decode_hex_32("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap());
        let mut path = ChainPath::default();
        path.added.push(block_hash);
        engine.apply_chain_path_update(path, block_hash, true);
        engine.best_effort_flush();

        let snapshot = engine.snapshot(true);
        assert_eq!(snapshot.entries.len(), 1, "expected one scored entry after promotion");
        assert_eq!(snapshot.entries[0].claimed_blocks, 1, "expected one claimed block after promotion");

        let reloaded = StrongNodeClaimsEngine::new(true, "mainnet", &temp_dir);
        let reloaded_snapshot = reloaded.snapshot(true);
        assert_eq!(reloaded_snapshot.entries.len(), 1, "expected one scored entry after reload");
        assert_eq!(reloaded_snapshot.entries[0].claimed_blocks, 1, "expected one claimed block after reload");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn hardfork_gating_ignores_claims_and_chain_updates_pre_hf() {
        let temp_dir = std::env::temp_dir().join(format!("strong-node-claims-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).expect("failed creating temp dir");
        let engine = StrongNodeClaimsEngine::new(true, "mainnet", &temp_dir);

        assert!(!engine.should_advertise_service_bit(false), "service bit must remain disabled pre-HF");

        let claim = build_signed_claim_message(
            0,
            "9e335f14f1a549c374a273b014e4e6658c666b9be6bb7478085510abcba7fae2",
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        );
        assert!(matches!(engine.ingest_claim(&claim, false), ClaimIngestOutcome::Ignored));

        let block_hash = Hash::from_bytes(decode_hex_32("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap());
        let mut path = ChainPath::default();
        path.added.push(block_hash);
        engine.apply_chain_path_update(path, block_hash, false);

        let snapshot = engine.snapshot(false);
        assert!(!snapshot.runtime_available, "runtime must remain unavailable pre-HF");
        assert!(snapshot.entries.is_empty(), "pre-HF updates must not mutate claim state");
        assert!(engine.last_sink().is_none(), "pre-HF updates must not advance sink");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn removed_blocks_purge_claim_state() {
        let temp_dir = std::env::temp_dir().join(format!("strong-node-claims-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).expect("failed creating temp dir");
        let engine = StrongNodeClaimsEngine::new(true, "mainnet", &temp_dir);

        let claim = build_signed_claim_message(
            0,
            "9e335f14f1a549c374a273b014e4e6658c666b9be6bb7478085510abcba7fae2",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        let outcome = engine.ingest_claim(&claim, true);
        match outcome {
            ClaimIngestOutcome::Accepted { pending } => assert!(pending, "claim should be pending before block is known"),
            other => panic!("unexpected ingest outcome: {other:?}"),
        }

        let block_hash = Hash::from_bytes(decode_hex_32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap());
        let mut add_path = ChainPath::default();
        add_path.added.push(block_hash);
        engine.apply_chain_path_update(add_path, block_hash, true);

        let mut remove_path = ChainPath::default();
        remove_path.removed.push(block_hash);
        engine.apply_chain_path_update(remove_path, block_hash, true);

        let state = engine.state.lock();
        assert!(!state.window_set.contains(&block_hash), "expected removed block to be absent from window set");
        assert!(!state.retention_set.contains(&block_hash), "expected removed block to be absent from retention set");
        assert!(!state.recent_claims_by_block.contains_key(&block_hash), "expected removed block to be absent from recent claims");
        assert!(!state.winning_claim_by_block.contains_key(&block_hash), "expected removed block to be absent from winners");
        assert!(!state.pending_unknown_claims.contains_key(&block_hash), "expected removed block to be absent from pending claims");
        assert!(state.score_by_node_id.is_empty(), "expected no remaining scores after removing the only claimed block");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    fn build_signed_claim_message(network_u8: u8, private_key_hex: &str, block_hash_hex: &str) -> BlockProducerClaimV1Message {
        let private_key = secp256k1::SecretKey::from_slice(&decode_hex_32(private_key_hex).unwrap()).unwrap();
        let keypair = Keypair::from_secret_key(secp256k1::SECP256K1, &private_key);
        let (pubkey_xonly, _) = XOnlyPublicKey::from_keypair(&keypair);
        let pubkey_xonly = pubkey_xonly.serialize();

        let node_id = *blake3::hash(&pubkey_xonly).as_bytes();
        let block_hash = Hash::from_bytes(decode_hex_32(block_hash_hex).unwrap());
        let claim_id = compute_claim_id(network_u8, &block_hash, &node_id);
        let secp_message = SecpMessage::from_digest_slice(&claim_id).unwrap();
        let signature = keypair.sign_schnorr(secp_message);

        BlockProducerClaimV1Message {
            schema_version: 1,
            network: network_u8 as u32,
            block_hash: block_hash.as_bytes().to_vec(),
            node_pubkey_xonly: pubkey_xonly.to_vec(),
            signature: signature.as_ref().to_vec(),
        }
    }
}
