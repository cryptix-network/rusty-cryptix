use crate::{
    error::{AtomicTokenError, AtomicTokenResult},
    liquidity_math::{
        calculate_trade_fee, cpmm_buy, cpmm_sell, initial_virtual_cpay_reserves_sompi_for_curve,
        initial_virtual_token_reserves_for_curve, min_gross_input_for_token_out, validate_liquidity_curve_mode,
        validate_liquidity_curve_parameters, LiquidityMathError, DEFAULT_LIQUIDITY_CURVE_MODE, INITIAL_REAL_CPAY_RESERVES_SOMPI,
        LIQUIDITY_MIN_PAYOUT_SOMPI, LIQUIDITY_TOKEN_DECIMALS, MAX_LIQUIDITY_SUPPLY_RAW, MIN_CPAY_RESERVE_SOMPI,
        MIN_LIQUIDITY_SEED_RESERVE_SOMPI, MIN_LIQUIDITY_SUPPLY_RAW, MIN_REAL_TOKEN_RESERVE,
    },
    payload::{
        parse_atomic_token_payload, ApplyStatus, BuyLiquidityExactInOp, ClaimLiquidityFeesOp, CreateAssetOp, CreateAssetWithMintOp,
        CreateLiquidityAssetOp, EventType, LiquidityRecipientAddress, MintOp, NoopReason, ParsedTokenPayload, SellLiquidityExactInOp,
        SupplyMode, TokenOp, TokenOpCode, CURRENT_LIQUIDITY_CURVE_VERSION, CURRENT_TOKEN_VERSION,
    },
    storage_v2::{compute_state_root_from_parts, AtomicStorageV2},
    IDENT,
};
use blake2b_simd::Params as Blake2bParams;
use cryptix_consensus_core::{
    acceptance_data::AcceptanceData,
    constants::MAX_SOMPI,
    tx::{ScriptPublicKey, Transaction, TransactionOutpoint, UtxoEntry},
    Hash as BlockHash,
};
use cryptix_consensus_notify::notification::VirtualChainChangedNotification;
use cryptix_consensusmanager::{ConsensusManager, ConsensusProxy};
use cryptix_core::{info, warn};
use cryptix_txscript::script_class::ScriptClass;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};

const CAT_OWNER_DOMAIN: &[u8] = b"CAT_OWNER_V2";
const OWNER_AUTH_SCHEME_PUBKEY: u8 = 0;
const OWNER_AUTH_SCHEME_PUBKEY_ECDSA: u8 = 1;
const OWNER_AUTH_SCHEME_SCRIPT_HASH: u8 = 2;
const LONG_ATOMIC_REPLAY_LOG_INTERVAL: Duration = Duration::from_secs(5);

const CAT_EVENT_DOMAIN: &[u8] = b"CAT_EVT_V2";
const CAT_EVENT_INSTANCE_DOMAIN: &[u8] = b"CAT_EVT_INSTANCE_V2";
pub const SNAPSHOT_SCHEMA_VERSION: u16 = 2;
pub const NONCE_SCOPE_OWNER: u8 = 0;
pub const NONCE_SCOPE_ASSET: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NonceKey {
    pub owner_id: [u8; 32],
    pub scope_kind: u8,
    pub scope_id: [u8; 32],
}

impl NonceKey {
    pub fn owner(owner_id: [u8; 32]) -> Self {
        Self { owner_id, scope_kind: NONCE_SCOPE_OWNER, scope_id: [0u8; 32] }
    }

    pub fn asset(owner_id: [u8; 32], asset_id: [u8; 32]) -> Self {
        Self { owner_id, scope_kind: NONCE_SCOPE_ASSET, scope_id: asset_id }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct VaultTransition {
    input_value: u64,
    output_index: u32,
    output_value: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AtomicTokenRuntimeState {
    NotReady,
    Healthy,
    Recovering,
    Degraded,
}

impl AtomicTokenRuntimeState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotReady => "not_ready",
            Self::Healthy => "healthy",
            Self::Recovering => "recovering",
            Self::Degraded => "degraded",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenEventDetails {
    pub op_type: Option<TokenOpCode>,
    pub asset_id: Option<[u8; 32]>,
    pub from_owner_id: Option<[u8; 32]>,
    pub to_owner_id: Option<[u8; 32]>,
    pub amount: Option<u128>,
}

impl Default for TokenEventDetails {
    fn default() -> Self {
        Self { op_type: None, asset_id: None, from_owner_id: None, to_owner_id: None, amount: None }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenEvent {
    pub event_id: [u8; 32],
    pub sequence: u64,
    pub accepting_block_hash: BlockHash,
    pub txid: BlockHash,
    pub event_type: EventType,
    pub apply_status: ApplyStatus,
    pub noop_reason: NoopReason,
    pub ordinal: u32,
    pub reorg_of_event_id: Option<[u8; 32]>,
    #[serde(default)]
    pub details: TokenEventDetails,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AtomicTokenHealth {
    pub is_degraded: bool,
    pub bootstrap_in_progress: bool,
    pub live_correct: bool,
    pub runtime_state: AtomicTokenRuntimeState,
    pub last_applied_block: Option<BlockHash>,
    pub last_sequence: u64,
    pub current_state_hash: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct AtomicTokenReadView {
    pub at_block_hash: BlockHash,
    pub state_hash: [u8; 32],
    pub is_degraded: bool,
    pub runtime_state: AtomicTokenRuntimeState,
    pub event_sequence_cutoff: u64,
    pub assets: HashMap<[u8; 32], TokenAsset>,
    pub balances: HashMap<BalanceKey, u128>,
    pub nonces: HashMap<NonceKey, u64>,
    pub anchor_counts: HashMap<[u8; 32], u64>,
    pub processed_ops: HashMap<BlockHash, ProcessedOp>,
    pub known_owner_addresses: HashMap<[u8; 32], LiquidityHolderAddressState>,
}

#[derive(Clone, Debug)]
pub struct AtomicTokenReadContext {
    pub at_block_hash: BlockHash,
    pub state_hash: [u8; 32],
    pub is_degraded: bool,
    pub runtime_state: AtomicTokenRuntimeState,
    pub event_sequence_cutoff: u64,
}

pub type TokenOwnerBalanceEntry = ([u8; 32], u128, Option<TokenAsset>);
pub type TokenHolderEntry = ([u8; 32], u128);

impl AtomicTokenReadView {
    pub fn context(&self) -> AtomicTokenReadContext {
        AtomicTokenReadContext {
            at_block_hash: self.at_block_hash,
            state_hash: self.state_hash,
            is_degraded: self.is_degraded,
            runtime_state: self.runtime_state,
            event_sequence_cutoff: self.event_sequence_cutoff,
        }
    }
}

#[cfg(test)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AtomicTokenSnapshot {
    pub schema_version: u16,
    pub protocol_version: u16,
    pub network_id: String,
    pub at_block_hash: BlockHash,
    pub at_daa_score: u64,
    pub state_hash_at_fp: [u8; 32],
    pub state_hash_at_window_start_parent: Option<[u8; 32]>,
    pub window_start_block_hash: BlockHash,
    pub window_start_parent_block_hash: BlockHash,
    pub window_end_block_hash: BlockHash,
    pub state: AtomicTokenSnapshotState,
    pub journals_in_window: Vec<(BlockHash, BlockJournal)>,
}

#[cfg(test)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AtomicTokenSnapshotState {
    pub assets: HashMap<[u8; 32], TokenAsset>,
    pub balances: HashMap<BalanceKey, u128>,
    pub nonces: HashMap<NonceKey, u64>,
    pub anchor_counts: HashMap<[u8; 32], u64>,
    pub processed_ops: HashMap<BlockHash, ProcessedOp>,
    pub state_hash_by_block: HashMap<BlockHash, [u8; 32]>,
    pub event_sequence_by_block: HashMap<BlockHash, u64>,
    pub applied_chain_order: Vec<BlockHash>,
    pub next_event_sequence: u64,
    pub events: Vec<TokenEvent>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenApplyResult {
    pub txid: BlockHash,
    pub apply_status: ApplyStatus,
    pub noop_reason: NoopReason,
    pub ordinal: u32,
    pub event_id: [u8; 32],
    #[serde(default)]
    pub details: TokenEventDetails,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BalanceKey {
    pub asset_id: [u8; 32],
    pub owner_id: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum TokenAssetClass {
    #[default]
    Standard,
    Liquidity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityFeeRecipientState {
    pub owner_id: [u8; 32],
    pub address_version: u8,
    pub address_payload: Vec<u8>,
    pub unclaimed_sompi: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityHolderAddressState {
    pub address_version: u8,
    pub address_payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityPoolState {
    pub pool_nonce: u64,
    #[serde(default = "default_liquidity_curve_version")]
    pub curve_version: u8,
    #[serde(default = "default_liquidity_curve_mode")]
    pub curve_mode: u8,
    #[serde(default)]
    pub individual_virtual_cpay_reserves_sompi: u64,
    #[serde(default)]
    pub individual_virtual_token_multiplier_bps: u16,
    pub real_cpay_reserves_sompi: u64,
    pub real_token_reserves: u128,
    pub virtual_cpay_reserves_sompi: u64,
    pub virtual_token_reserves: u128,
    pub unclaimed_fee_total_sompi: u64,
    pub fee_bps: u16,
    pub fee_recipients: Vec<LiquidityFeeRecipientState>,
    pub vault_outpoint: TransactionOutpoint,
    pub vault_value_sompi: u64,
    #[serde(default)]
    pub unlock_target_sompi: u64,
    #[serde(default = "default_liquidity_unlocked")]
    pub unlocked: bool,
    #[serde(default)]
    pub holder_addresses: HashMap<[u8; 32], LiquidityHolderAddressState>,
}

fn default_liquidity_unlocked() -> bool {
    true
}

fn default_liquidity_curve_version() -> u8 {
    CURRENT_LIQUIDITY_CURVE_VERSION
}

fn default_liquidity_curve_mode() -> u8 {
    DEFAULT_LIQUIDITY_CURVE_MODE
}

fn default_token_version() -> u8 {
    CURRENT_TOKEN_VERSION
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenAsset {
    pub asset_id: [u8; 32],
    pub creator_owner_id: [u8; 32],
    #[serde(default)]
    pub asset_class: TokenAssetClass,
    #[serde(default = "default_token_version")]
    pub token_version: u8,
    pub mint_authority_owner_id: [u8; 32],
    pub decimals: u8,
    pub supply_mode: SupplyMode,
    pub max_supply: u128,
    pub total_supply: u128,
    pub name: Vec<u8>,
    pub symbol: Vec<u8>,
    pub metadata: Vec<u8>,
    #[serde(default)]
    pub platform_tag: Vec<u8>,
    #[serde(default)]
    pub created_block_hash: Option<BlockHash>,
    #[serde(default)]
    pub created_daa_score: Option<u64>,
    #[serde(default)]
    pub created_at: Option<u64>,
    #[serde(default)]
    pub liquidity: Option<LiquidityPoolState>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessedOp {
    pub accepting_block_hash: BlockHash,
    pub apply_status: ApplyStatus,
    pub noop_reason: NoopReason,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangedAsset {
    pub asset_id: [u8; 32],
    pub old_value: Option<TokenAsset>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangedBalance {
    pub key: BalanceKey,
    pub old_value: Option<u128>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangedNonce {
    pub key: NonceKey,
    pub old_value: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangedAnchorCount {
    pub owner_id: [u8; 32],
    pub old_value: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BlockJournal {
    pub changed_assets: Vec<ChangedAsset>,
    pub changed_balances: Vec<ChangedBalance>,
    pub changed_nonces: Vec<ChangedNonce>,
    pub changed_anchor_counts: Vec<ChangedAnchorCount>,
    pub added_processed_ops: Vec<BlockHash>,
    pub tx_results: Vec<TokenApplyResult>,
}

#[derive(Debug, Default)]
struct JournalBuilder {
    changed_assets: Vec<ChangedAsset>,
    changed_balances: Vec<ChangedBalance>,
    changed_nonces: Vec<ChangedNonce>,
    changed_anchor_counts: Vec<ChangedAnchorCount>,
    added_processed_ops: Vec<BlockHash>,
    tx_results: Vec<TokenApplyResult>,
    seen_assets: HashSet<[u8; 32]>,
    seen_balances: HashSet<BalanceKey>,
    seen_nonces: HashSet<NonceKey>,
    seen_anchor_counts: HashSet<[u8; 32]>,
}

#[derive(Default)]
struct StorageDelta {
    assets: Vec<([u8; 32], Option<TokenAsset>)>,
    balances: Vec<(BalanceKey, Option<u128>)>,
    nonces: Vec<(NonceKey, Option<u64>)>,
    anchor_counts: Vec<([u8; 32], Option<u64>)>,
    processed_ops: Vec<(BlockHash, Option<ProcessedOp>)>,
}

impl JournalBuilder {
    fn into_block_journal(self) -> BlockJournal {
        BlockJournal {
            changed_assets: self.changed_assets,
            changed_balances: self.changed_balances,
            changed_nonces: self.changed_nonces,
            changed_anchor_counts: self.changed_anchor_counts,
            added_processed_ops: self.added_processed_ops,
            tx_results: self.tx_results,
        }
    }
}

#[derive(Clone)]
struct AuthContext {
    owner_id: [u8; 32],
    address_version: u8,
    address_payload: Vec<u8>,
}

fn token_op_allows_liquidity_vault_output(op: &TokenOp) -> bool {
    matches!(
        op,
        TokenOp::CreateLiquidityAsset(_)
            | TokenOp::BuyLiquidityExactIn(_)
            | TokenOp::SellLiquidityExactIn(_)
            | TokenOp::ClaimLiquidityFees(_)
    )
}

pub fn nonce_key_for_op(owner_id: [u8; 32], op: &TokenOp) -> NonceKey {
    match op {
        TokenOp::CreateAsset(_) | TokenOp::CreateAssetWithMint(_) | TokenOp::CreateLiquidityAsset(_) => NonceKey::owner(owner_id),
        TokenOp::Transfer(op) => NonceKey::asset(owner_id, op.asset_id),
        TokenOp::Mint(op) => NonceKey::asset(owner_id, op.asset_id),
        TokenOp::Burn(op) => NonceKey::asset(owner_id, op.asset_id),
        TokenOp::BuyLiquidityExactIn(op) => NonceKey::asset(owner_id, op.asset_id),
        TokenOp::SellLiquidityExactIn(op) => NonceKey::asset(owner_id, op.asset_id),
        TokenOp::ClaimLiquidityFees(op) => NonceKey::asset(owner_id, op.asset_id),
    }
}

fn asset_matches_query(asset: &TokenAsset, query: &str) -> bool {
    let query = query.trim().to_ascii_lowercase();
    if query.is_empty() {
        return true;
    }

    let symbol = String::from_utf8_lossy(&asset.symbol).to_ascii_lowercase();
    let name = String::from_utf8_lossy(&asset.name).to_ascii_lowercase();
    let asset_id = hex_lower(&asset.asset_id);
    symbol.contains(&query) || name.contains(&query) || asset_id.starts_with(&query)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn validate_liquidity_claim_authorization(claimant_owner_id: [u8; 32], recipient_owner_id: [u8; 32]) -> Result<(), NoopReason> {
    if claimant_owner_id == recipient_owner_id {
        Ok(())
    } else {
        Err(NoopReason::BadAuthInput)
    }
}

fn validate_real_cpay_reserve(real_cpay_reserves_sompi: u64) -> Result<(), NoopReason> {
    if real_cpay_reserves_sompi < MIN_CPAY_RESERVE_SOMPI {
        Err(NoopReason::InternalMalformedAcceptance)
    } else {
        Ok(())
    }
}

fn liquidity_sell_locked(pool: &LiquidityPoolState) -> bool {
    pool.unlock_target_sompi > 0 && !pool.unlocked
}

fn validate_liquidity_unlock_target(unlock_target_sompi: u64) -> Result<(), NoopReason> {
    if unlock_target_sompi == 0 || unlock_target_sompi <= MAX_SOMPI {
        Ok(())
    } else {
        Err(NoopReason::BadLiquidityUnlockTarget)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct CanonicalTxRef {
    txid: BlockHash,
    source_block_hash: BlockHash,
    source_block_daa_score: u64,
    source_block_time: u64,
    tx_index: u32,
    acceptance_entry_position: u32,
    tx: Transaction,
}

struct NormalizedAcceptance {
    refs: Vec<CanonicalTxRef>,
    conflicting_txids: HashSet<BlockHash>,
}

fn normalize_acceptance_refs(_accepting_block_hash: BlockHash, refs: Vec<CanonicalTxRef>) -> AtomicTokenResult<NormalizedAcceptance> {
    let mut seen_semantics: HashMap<BlockHash, (BlockHash, u32)> = HashMap::new();
    let mut unique_refs = Vec::with_capacity(refs.len());
    let mut conflicting_txids = HashSet::new();

    for tx_ref in refs {
        let semantics = (tx_ref.source_block_hash, tx_ref.tx_index);
        if let Some(previous) = seen_semantics.get(&tx_ref.txid).copied() {
            if previous != semantics {
                conflicting_txids.insert(tx_ref.txid);
                continue;
            }
            continue;
        }
        seen_semantics.insert(tx_ref.txid, semantics);
        unique_refs.push(tx_ref);
    }

    Ok(NormalizedAcceptance { refs: unique_refs, conflicting_txids })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AtomicTokenState {
    pub protocol_version: u16,
    pub network_id: String,
    pub degraded: bool,
    pub live_correct: bool,
    pub assets: HashMap<[u8; 32], TokenAsset>,
    pub balances: HashMap<BalanceKey, u128>,
    pub nonces: HashMap<NonceKey, u64>,
    pub anchor_counts: HashMap<[u8; 32], u64>,
    pub processed_ops: HashMap<BlockHash, ProcessedOp>,
    pub block_journals: HashMap<BlockHash, BlockJournal>,
    pub state_hash_by_block: HashMap<BlockHash, [u8; 32]>,
    pub event_sequence_by_block: HashMap<BlockHash, u64>,
    pub applied_chain_order: Vec<BlockHash>,
    pub next_event_sequence: u64,
    pub events: Vec<TokenEvent>,
    #[serde(skip, default)]
    event_ids: HashSet<[u8; 32]>,
    #[serde(skip, default)]
    payload_hf_activation_daa_score: u64,
    #[serde(skip, default)]
    liquidity_vault_outpoints: HashMap<TransactionOutpoint, [u8; 32]>,
    #[serde(skip, default)]
    known_owner_addresses: HashMap<[u8; 32], LiquidityHolderAddressState>,
    #[serde(skip, default)]
    balances_by_owner: HashMap<[u8; 32], HashSet<[u8; 32]>>,
    #[serde(skip, default)]
    holders_by_asset: HashMap<[u8; 32], HashSet<[u8; 32]>>,
    #[serde(skip, default)]
    state_store: Option<Arc<AtomicStorageV2>>,
    #[serde(skip, default)]
    deleted_assets: HashSet<[u8; 32]>,
    #[serde(skip, default)]
    deleted_balances: HashSet<BalanceKey>,
    #[serde(skip, default)]
    deleted_nonces: HashSet<NonceKey>,
    #[serde(skip, default)]
    deleted_anchor_counts: HashSet<[u8; 32]>,
    #[serde(skip, default)]
    deleted_processed_ops: HashSet<BlockHash>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct AtomicTokenStateFootprint {
    pub assets: usize,
    pub balances: usize,
    pub nonces: usize,
    pub anchor_counts: usize,
    pub processed_ops: usize,
    pub block_journals: usize,
    pub state_hash_checkpoints: usize,
    pub event_sequence_checkpoints: usize,
    pub retained_blocks: usize,
    pub events: usize,
    pub liquidity_vault_outpoints: usize,
    pub known_owner_addresses: usize,
    pub owners_with_balances: usize,
    pub assets_with_holders: usize,
}

pub struct AtomicTokenPruneResult {
    pub pruned_hashes: Vec<BlockHash>,
    pub pruned_processed_op_txids: Vec<BlockHash>,
    pub last_pruned_event_sequence: Option<u64>,
    pub pruned_processed_ops: bool,
}

impl AtomicTokenState {
    pub fn new(protocol_version: u16, network_id: String) -> Self {
        Self {
            protocol_version,
            network_id,
            degraded: false,
            live_correct: false,
            assets: Default::default(),
            balances: Default::default(),
            nonces: Default::default(),
            anchor_counts: Default::default(),
            processed_ops: Default::default(),
            block_journals: Default::default(),
            state_hash_by_block: Default::default(),
            event_sequence_by_block: Default::default(),
            applied_chain_order: Default::default(),
            next_event_sequence: 0,
            events: Default::default(),
            event_ids: Default::default(),
            payload_hf_activation_daa_score: 0,
            liquidity_vault_outpoints: Default::default(),
            known_owner_addresses: Default::default(),
            balances_by_owner: Default::default(),
            holders_by_asset: Default::default(),
            state_store: None,
            deleted_assets: Default::default(),
            deleted_balances: Default::default(),
            deleted_nonces: Default::default(),
            deleted_anchor_counts: Default::default(),
            deleted_processed_ops: Default::default(),
        }
    }

    pub fn attach_state_store(&mut self, state_store: Arc<AtomicStorageV2>) {
        self.state_store = Some(state_store);
    }

    pub fn assets_missing_permanent_metadata(&self) -> Vec<[u8; 32]> {
        let mut asset_ids = self
            .assets
            .iter()
            .filter_map(|(asset_id, asset)| {
                let missing_creation_metadata =
                    asset.created_block_hash.is_none() || asset.created_daa_score.is_none() || asset.created_at.is_none();
                missing_creation_metadata.then_some(*asset_id)
            })
            .collect::<Vec<_>>();
        asset_ids.sort_unstable();
        asset_ids
    }

    pub async fn recover_missing_asset_metadata_from_retained_acceptance(
        &mut self,
        retained_chain: &[BlockHash],
        acceptance_data: &[Arc<AcceptanceData>],
        auth_inputs: &HashMap<TransactionOutpoint, UtxoEntry>,
        session: &ConsensusProxy,
    ) -> AtomicTokenResult<Vec<TokenAsset>> {
        if retained_chain.len() != acceptance_data.len() {
            return Err(AtomicTokenError::Processing(format!(
                "failed recovering permanent Atomic asset metadata: acceptance-data length mismatch ({} != {})",
                acceptance_data.len(),
                retained_chain.len()
            )));
        }

        let mut candidates = self.assets.keys().copied().collect::<HashSet<_>>();
        if candidates.is_empty() {
            return Ok(Vec::new());
        }

        let mut repaired = Vec::new();
        for (accepting_block_hash, block_acceptance_data) in retained_chain.iter().copied().zip(acceptance_data.iter()) {
            let normalized = self.flatten_acceptance_for_block(accepting_block_hash, block_acceptance_data, session).await?;
            for tx_ref in normalized.refs.iter() {
                if candidates.is_empty() {
                    return Ok(repaired);
                }
                let asset_id = tx_ref.tx.id().as_bytes();
                if !candidates.contains(&asset_id) {
                    continue;
                }
                let Some(Ok(parsed)) = parse_atomic_token_payload(&tx_ref.tx.payload) else {
                    continue;
                };
                let Some(asset) = self.assets.get(&asset_id).cloned() else {
                    continue;
                };
                let Ok(auth_context) = self.resolve_auth_context(&tx_ref.tx, parsed.header.auth_input_index, auth_inputs) else {
                    continue;
                };
                let mut repaired_asset = asset.clone();
                match parsed.op {
                    TokenOp::CreateAsset(op) => {
                        repaired_asset.creator_owner_id = auth_context.owner_id;
                        repaired_asset.asset_class = TokenAssetClass::Standard;
                        repaired_asset.token_version = op.token_version;
                        repaired_asset.mint_authority_owner_id = op.mint_authority_owner_id;
                        repaired_asset.decimals = op.decimals;
                        repaired_asset.supply_mode = op.supply_mode;
                        repaired_asset.max_supply = op.max_supply;
                        repaired_asset.name = op.name;
                        repaired_asset.symbol = op.symbol;
                        repaired_asset.metadata = op.metadata;
                        repaired_asset.platform_tag = op.platform_tag;
                    }
                    TokenOp::CreateAssetWithMint(op) => {
                        repaired_asset.creator_owner_id = auth_context.owner_id;
                        repaired_asset.asset_class = TokenAssetClass::Standard;
                        repaired_asset.token_version = op.token_version;
                        repaired_asset.mint_authority_owner_id = op.mint_authority_owner_id;
                        repaired_asset.decimals = op.decimals;
                        repaired_asset.supply_mode = op.supply_mode;
                        repaired_asset.max_supply = op.max_supply;
                        repaired_asset.name = op.name;
                        repaired_asset.symbol = op.symbol;
                        repaired_asset.metadata = op.metadata;
                        repaired_asset.platform_tag = op.platform_tag;
                    }
                    TokenOp::CreateLiquidityAsset(op) => {
                        repaired_asset.creator_owner_id = auth_context.owner_id;
                        repaired_asset.asset_class = TokenAssetClass::Liquidity;
                        repaired_asset.token_version = op.token_version;
                        repaired_asset.mint_authority_owner_id = [0u8; 32];
                        repaired_asset.decimals = op.decimals;
                        repaired_asset.supply_mode = SupplyMode::Capped;
                        repaired_asset.max_supply = op.max_supply;
                        repaired_asset.name = op.name;
                        repaired_asset.symbol = op.symbol;
                        repaired_asset.metadata = op.metadata;
                        repaired_asset.platform_tag = op.platform_tag;
                    }
                    _ => continue,
                }
                repaired_asset.created_block_hash = Some(tx_ref.source_block_hash);
                repaired_asset.created_daa_score = Some(tx_ref.source_block_daa_score);
                repaired_asset.created_at = Some(tx_ref.source_block_time);
                if repaired_asset != asset {
                    self.assets.insert(asset_id, repaired_asset.clone());
                    repaired.push(repaired_asset);
                }
                candidates.remove(&asset_id);
            }
        }
        Ok(repaired)
    }

    pub fn detach_state_store(&mut self) {
        self.state_store = None;
    }

    pub fn footprint(&self) -> AtomicTokenStateFootprint {
        AtomicTokenStateFootprint {
            assets: self.assets.len(),
            balances: self.balances.len(),
            nonces: self.nonces.len(),
            anchor_counts: self.anchor_counts.len(),
            processed_ops: self.processed_ops.len(),
            block_journals: self.block_journals.len(),
            state_hash_checkpoints: self.state_hash_by_block.len(),
            event_sequence_checkpoints: self.event_sequence_by_block.len(),
            retained_blocks: self.applied_chain_order.len(),
            events: self.events.len(),
            liquidity_vault_outpoints: self.liquidity_vault_outpoints.len(),
            known_owner_addresses: self.known_owner_addresses.len(),
            owners_with_balances: self.balances_by_owner.len(),
            assets_with_holders: self.holders_by_asset.len(),
        }
    }

    pub fn set_payload_hf_activation_daa_score(&mut self, daa_score: u64) {
        self.payload_hf_activation_daa_score = daa_score;
    }

    pub fn rebuild_runtime_caches(&mut self) {
        self.rebuild_liquidity_vault_outpoint_index();
        self.rebuild_known_owner_address_cache();
        self.rebuild_balance_indices();
    }

    fn rebuild_liquidity_vault_outpoint_index(&mut self) {
        self.liquidity_vault_outpoints.clear();
        for (asset_id, asset) in self.assets.iter() {
            let Some(pool) = asset.liquidity.as_ref() else {
                continue;
            };
            if !matches!(asset.asset_class, TokenAssetClass::Liquidity) {
                continue;
            }
            self.liquidity_vault_outpoints.insert(pool.vault_outpoint, *asset_id);
        }
    }

    fn rebuild_known_owner_address_cache(&mut self) {
        self.known_owner_addresses = Self::known_owner_addresses_from_assets(&self.assets);
    }

    fn known_owner_addresses_from_assets(assets: &HashMap<[u8; 32], TokenAsset>) -> HashMap<[u8; 32], LiquidityHolderAddressState> {
        let mut known_owner_addresses = HashMap::new();
        for asset in assets.values() {
            let Some(pool) = asset.liquidity.as_ref() else {
                continue;
            };
            for recipient in pool.fee_recipients.iter() {
                known_owner_addresses.entry(recipient.owner_id).or_insert_with(|| LiquidityHolderAddressState {
                    address_version: recipient.address_version,
                    address_payload: recipient.address_payload.clone(),
                });
            }
            for (owner_id, holder) in pool.holder_addresses.iter() {
                known_owner_addresses.entry(*owner_id).or_insert_with(|| holder.clone());
            }
        }
        known_owner_addresses
    }

    fn remember_owner_address(&mut self, owner_id: [u8; 32], address_version: u8, address_payload: &[u8]) {
        self.known_owner_addresses
            .entry(owner_id)
            .or_insert_with(|| LiquidityHolderAddressState { address_version, address_payload: address_payload.to_vec() });
    }

    fn asset_value(&self, asset_id: &[u8; 32]) -> Option<TokenAsset> {
        if let Some(asset) = self.assets.get(asset_id) {
            return Some(asset.clone());
        }
        if self.deleted_assets.contains(asset_id) {
            return None;
        }
        self.state_store.as_ref().and_then(|store| store.get_asset(asset_id).ok().flatten())
    }

    fn balance_value(&self, key: &BalanceKey) -> u128 {
        if let Some(balance) = self.balances.get(key) {
            return *balance;
        }
        if self.deleted_balances.contains(key) {
            return 0;
        }
        self.state_store.as_ref().and_then(|store| store.get_balance(key).ok()).unwrap_or(0)
    }

    fn nonce_value(&self, key: &NonceKey) -> u64 {
        if let Some(nonce) = self.nonces.get(key) {
            return *nonce;
        }
        if self.deleted_nonces.contains(key) {
            return 1;
        }
        self.state_store.as_ref().and_then(|store| store.get_nonce(key).ok()).unwrap_or(1)
    }

    fn anchor_count_value(&self, owner_id: &[u8; 32]) -> u64 {
        if let Some(count) = self.anchor_counts.get(owner_id) {
            return *count;
        }
        if self.deleted_anchor_counts.contains(owner_id) {
            return 0;
        }
        self.state_store.as_ref().and_then(|store| store.get_anchor_count(owner_id).ok()).unwrap_or(0)
    }

    fn processed_op_value(&self, txid: &BlockHash) -> Option<ProcessedOp> {
        if let Some(op) = self.processed_ops.get(txid) {
            return Some(op.clone());
        }
        if self.deleted_processed_ops.contains(txid) {
            return None;
        }
        self.state_store.as_ref().and_then(|store| store.get_processed_op(txid).ok().flatten())
    }

    fn processed_op_value_strict(&self, txid: &BlockHash) -> AtomicTokenResult<Option<ProcessedOp>> {
        if let Some(op) = self.processed_ops.get(txid) {
            return Ok(Some(op.clone()));
        }
        if self.deleted_processed_ops.contains(txid) {
            return Ok(None);
        }
        match self.state_store.as_ref() {
            Some(store) => store.get_processed_op(txid),
            None => Ok(None),
        }
    }

    fn clear_storage_overlay(&mut self) {
        self.assets.clear();
        self.balances.clear();
        self.nonces.clear();
        self.anchor_counts.clear();
        self.processed_ops.clear();
        self.deleted_assets.clear();
        self.deleted_balances.clear();
        self.deleted_nonces.clear();
        self.deleted_anchor_counts.clear();
        self.deleted_processed_ops.clear();
        self.liquidity_vault_outpoints.clear();
        self.known_owner_addresses.clear();
        self.balances_by_owner.clear();
        self.holders_by_asset.clear();
    }

    pub fn clear_persistent_state_overlay(&mut self) {
        self.clear_storage_overlay();
    }

    pub fn reset_to_empty_replay_state(&mut self, state_store: Arc<AtomicStorageV2>) {
        self.attach_state_store(state_store);
        self.clear_storage_overlay();
        self.block_journals.clear();
        self.state_hash_by_block.clear();
        self.event_sequence_by_block.clear();
        self.applied_chain_order.clear();
        self.next_event_sequence = 0;
        self.events.clear();
        self.event_ids.clear();
        self.degraded = false;
        self.live_correct = false;
    }

    fn storage_delta_for_applied_journal(&self, journal: &BlockJournal) -> StorageDelta {
        let mut delta = StorageDelta::default();
        for change in journal.changed_assets.iter() {
            delta.assets.push((change.asset_id, self.asset_value(&change.asset_id)));
        }
        for change in journal.changed_balances.iter() {
            let value = self.balance_value(&change.key);
            delta.balances.push((change.key, (value > 0).then_some(value)));
        }
        for change in journal.changed_nonces.iter() {
            let value = self.nonce_value(&change.key);
            delta.nonces.push((change.key, (value != 1).then_some(value)));
        }
        for change in journal.changed_anchor_counts.iter() {
            let value = self.anchor_count_value(&change.owner_id);
            delta.anchor_counts.push((change.owner_id, (value > 0).then_some(value)));
        }
        for txid in journal.added_processed_ops.iter().copied() {
            delta.processed_ops.push((txid, self.processed_op_value(&txid)));
        }
        delta
    }

    fn storage_delta_for_rollback_journal(journal: &BlockJournal) -> StorageDelta {
        let mut delta = StorageDelta::default();
        for change in journal.changed_assets.iter() {
            delta.assets.push((change.asset_id, change.old_value.clone()));
        }
        for change in journal.changed_balances.iter() {
            delta.balances.push((change.key, change.old_value));
        }
        for change in journal.changed_nonces.iter() {
            delta.nonces.push((change.key, change.old_value));
        }
        for change in journal.changed_anchor_counts.iter() {
            delta.anchor_counts.push((change.owner_id, change.old_value));
        }
        for txid in journal.added_processed_ops.iter().copied() {
            delta.processed_ops.push((txid, None));
        }
        delta
    }

    fn rebuild_balance_indices(&mut self) {
        self.balances_by_owner.clear();
        self.holders_by_asset.clear();
        self.deleted_balances.clear();
        let keys = self.balances.keys().copied().collect::<Vec<_>>();
        for key in keys {
            if self.balance_value(&key) > 0 {
                self.index_balance_key(key);
            }
        }
    }

    fn index_balance_key(&mut self, key: BalanceKey) {
        self.balances_by_owner.entry(key.owner_id).or_default().insert(key.asset_id);
        self.holders_by_asset.entry(key.asset_id).or_default().insert(key.owner_id);
    }

    fn unindex_balance_key(&mut self, key: BalanceKey) {
        if let Some(asset_ids) = self.balances_by_owner.get_mut(&key.owner_id) {
            asset_ids.remove(&key.asset_id);
            if asset_ids.is_empty() {
                self.balances_by_owner.remove(&key.owner_id);
            }
        }
        if let Some(owner_ids) = self.holders_by_asset.get_mut(&key.asset_id) {
            owner_ids.remove(&key.owner_id);
            if owner_ids.is_empty() {
                self.holders_by_asset.remove(&key.asset_id);
            }
        }
    }

    fn set_balance_amount(&mut self, key: BalanceKey, amount: u128) {
        if amount == 0 {
            self.remove_balance(key);
        } else {
            self.deleted_balances.remove(&key);
            self.balances.insert(key, amount);
            self.index_balance_key(key);
        }
    }

    fn remove_balance(&mut self, key: BalanceKey) {
        self.balances.remove(&key);
        self.deleted_balances.insert(key);
        self.unindex_balance_key(key);
    }

    fn set_asset_state(&mut self, asset_id: [u8; 32], asset: TokenAsset) {
        let previous_asset = self.asset_value(&asset_id);
        self.deleted_assets.remove(&asset_id);
        self.assets.insert(asset_id, asset.clone());
        if let Some(previous_asset) = previous_asset {
            if let Some(previous_pool) = previous_asset.liquidity.as_ref() {
                self.liquidity_vault_outpoints.remove(&previous_pool.vault_outpoint);
            }
        }

        if matches!(asset.asset_class, TokenAssetClass::Liquidity) {
            if let Some(pool) = asset.liquidity.as_ref() {
                self.liquidity_vault_outpoints.insert(pool.vault_outpoint, asset_id);
                for recipient in pool.fee_recipients.iter() {
                    self.remember_owner_address(recipient.owner_id, recipient.address_version, recipient.address_payload.as_slice());
                }
                for (owner_id, holder) in pool.holder_addresses.iter() {
                    self.remember_owner_address(*owner_id, holder.address_version, holder.address_payload.as_slice());
                }
            }
        }
    }

    fn remove_asset_state(&mut self, asset_id: [u8; 32]) {
        let previous_asset = self.asset_value(&asset_id);
        self.assets.remove(&asset_id);
        self.deleted_assets.insert(asset_id);
        if let Some(previous_asset) = previous_asset {
            if let Some(previous_pool) = previous_asset.liquidity.as_ref() {
                self.liquidity_vault_outpoints.remove(&previous_pool.vault_outpoint);
            }
        }
        self.rebuild_known_owner_address_cache();
    }

    fn set_nonce_value(&mut self, key: NonceKey, value: u64) {
        self.deleted_nonces.remove(&key);
        self.nonces.insert(key, value);
    }

    fn remove_nonce_value(&mut self, key: NonceKey) {
        self.nonces.remove(&key);
        self.deleted_nonces.insert(key);
    }

    fn set_anchor_count_value(&mut self, owner_id: [u8; 32], value: u64) {
        if value == 0 {
            self.remove_anchor_count_value(owner_id);
        } else {
            self.deleted_anchor_counts.remove(&owner_id);
            self.anchor_counts.insert(owner_id, value);
        }
    }

    fn remove_anchor_count_value(&mut self, owner_id: [u8; 32]) {
        self.anchor_counts.remove(&owner_id);
        self.deleted_anchor_counts.insert(owner_id);
    }

    fn set_processed_op_value(&mut self, txid: BlockHash, op: ProcessedOp) {
        self.deleted_processed_ops.remove(&txid);
        self.processed_ops.insert(txid, op);
    }

    fn remove_processed_op_value(&mut self, txid: BlockHash) {
        self.processed_ops.remove(&txid);
        self.deleted_processed_ops.insert(txid);
    }

    pub fn mark_degraded(&mut self) {
        self.degraded = true;
        self.live_correct = false;
    }

    pub fn has_verified_state(&self) -> bool {
        self.applied_chain_order.last().is_some()
    }

    pub fn first_replayable_block_hash(&self) -> Option<BlockHash> {
        let mut index = self.applied_chain_order.len().checked_sub(1)?;
        if !self.block_journals.contains_key(&self.applied_chain_order[index]) {
            return None;
        }
        while index > 0 && self.block_journals.contains_key(&self.applied_chain_order[index - 1]) {
            index -= 1;
        }
        Some(self.applied_chain_order[index])
    }

    pub fn runtime_state(&self, bootstrap_in_progress: bool) -> AtomicTokenRuntimeState {
        if self.degraded {
            AtomicTokenRuntimeState::Degraded
        } else if bootstrap_in_progress {
            AtomicTokenRuntimeState::Recovering
        } else if !self.live_correct || !self.has_verified_state() {
            AtomicTokenRuntimeState::NotReady
        } else {
            AtomicTokenRuntimeState::Healthy
        }
    }

    fn commit_applied_block_to_store(
        &mut self,
        accepting_block_hash: BlockHash,
        journal: &BlockJournal,
        chain_index: u64,
        event_sequence: u64,
        new_events: &[TokenEvent],
    ) -> AtomicTokenResult<Option<[u8; 32]>> {
        let Some(store) = self.state_store.as_ref() else {
            return Ok(None);
        };
        let delta = self.storage_delta_for_applied_journal(journal);
        let root = store.commit_applied_block_delta(
            delta.assets,
            delta.balances,
            delta.nonces,
            delta.anchor_counts,
            delta.processed_ops,
            accepting_block_hash,
            journal,
            chain_index,
            event_sequence,
            new_events,
            self.degraded,
            self.next_event_sequence,
        )?;
        self.clear_storage_overlay();
        Ok(Some(root))
    }

    fn commit_rollback_to_store(
        &mut self,
        removed_block_hash: BlockHash,
        journal: &BlockJournal,
        new_events: &[TokenEvent],
    ) -> AtomicTokenResult<Option<[u8; 32]>> {
        let Some(store) = self.state_store.as_ref() else {
            return Ok(None);
        };
        let delta = Self::storage_delta_for_rollback_journal(journal);
        let root = store.commit_rollback_delta(
            delta.assets,
            delta.balances,
            delta.nonces,
            delta.anchor_counts,
            delta.processed_ops,
            removed_block_hash,
            self.applied_chain_order.last().copied(),
            self.applied_chain_order.len() as u64,
            new_events,
            self.degraded,
            self.next_event_sequence,
        )?;
        self.clear_storage_overlay();
        Ok(Some(root))
    }

    pub async fn apply_virtual_chain_change(
        &mut self,
        notification: &VirtualChainChangedNotification,
        auth_inputs: &HashMap<TransactionOutpoint, UtxoEntry>,
        consensus_manager: &Arc<ConsensusManager>,
    ) -> AtomicTokenResult<()> {
        if self.degraded {
            return Ok(());
        }

        let removed_total = notification.removed_chain_block_hashes.len();
        let added_total = notification.added_chain_block_hashes.len();
        let should_log_long_replay = removed_total.saturating_add(added_total) >= 1024;
        let mut last_replay_log = Instant::now();
        if should_log_long_replay {
            info!("[{IDENT}] Cryptix Atomic applying virtual-chain update: +{} / -{} block(s)", added_total, removed_total);
        }

        for (idx, removed_block_hash) in notification.removed_chain_block_hashes.iter().copied().enumerate() {
            let old_event_len = self.events.len();
            let rollback_journal = match self.rollback_block(removed_block_hash) {
                Ok(journal) => journal,
                Err(()) => {
                    self.mark_degraded();
                    return Err(AtomicTokenError::Processing(format!(
                        "Cryptix Atomic cannot rollback block `{removed_block_hash}` because journal is missing"
                    )));
                }
            };
            let new_events = self.events[old_event_len..].to_vec();
            if let Err(err) = self.commit_rollback_to_store(removed_block_hash, &rollback_journal, &new_events) {
                self.mark_degraded();
                return Err(AtomicTokenError::Processing(format!(
                    "Cryptix Atomic failed persisting rollback for block `{removed_block_hash}`: {err}"
                )));
            }
            if should_log_long_replay && last_replay_log.elapsed() >= LONG_ATOMIC_REPLAY_LOG_INTERVAL {
                info!(
                    "[{IDENT}] Cryptix Atomic virtual-chain rollback progress: {}/{} block(s)",
                    idx.saturating_add(1),
                    removed_total
                );
                last_replay_log = Instant::now();
            }
        }

        let consensus = consensus_manager.consensus();
        let session = consensus.session().await;

        for (idx, accepting_block_hash) in notification.added_chain_block_hashes.iter().copied().enumerate() {
            let old_event_len = self.events.len();
            let accepting_header = session.async_get_header(accepting_block_hash).await.map_err(|err| {
                self.mark_degraded();
                AtomicTokenError::Processing(format!(
                    "failed reading accepting block header `{accepting_block_hash}` during Atomic state transition: {err}"
                ))
            })?;
            let acceptance_data = notification
                .added_chain_blocks_acceptance_data
                .get(idx)
                .ok_or_else(|| AtomicTokenError::Processing("missing acceptance data for added chain block".to_string()))?;

            let normalized = match self.flatten_acceptance_for_block(accepting_block_hash, acceptance_data.as_ref(), &session).await {
                Ok(refs) => refs,
                Err(err) => {
                    self.mark_degraded();
                    return Err(err);
                }
            };

            let mut journal = JournalBuilder::default();
            if !normalized.conflicting_txids.is_empty() {
                for (ordinal, tx_ref) in normalized.refs.into_iter().enumerate() {
                    self.insert_internal_malformed_noop(
                        accepting_block_hash,
                        accepting_header.daa_score,
                        &tx_ref,
                        ordinal as u32,
                        &mut journal,
                    );
                }
                self.mark_degraded();
                let block_journal = journal.into_block_journal();
                let event_sequence = self.next_event_sequence;
                let chain_index = self.applied_chain_order.len() as u64;
                let new_events = self.events[old_event_len..].to_vec();
                let state_hash = self
                    .commit_applied_block_to_store(accepting_block_hash, &block_journal, chain_index, event_sequence, &new_events)?
                    .unwrap_or_else(|| self.compute_state_hash());
                self.block_journals.insert(accepting_block_hash, block_journal);
                self.state_hash_by_block.insert(accepting_block_hash, state_hash);
                self.event_sequence_by_block.insert(accepting_block_hash, event_sequence);
                self.applied_chain_order.push(accepting_block_hash);
                return Err(AtomicTokenError::Degraded(format!(
                    "malformed acceptance data for accepting block `{accepting_block_hash}`: duplicate txid with incompatible semantics"
                )));
            }

            for (ordinal, tx_ref) in normalized.refs.into_iter().enumerate() {
                let apply_anchor_deltas = self.apply_transaction(
                    accepting_block_hash,
                    accepting_header.daa_score,
                    accepting_header.timestamp,
                    &tx_ref,
                    ordinal as u32,
                    auth_inputs,
                    &mut journal,
                );
                if apply_anchor_deltas {
                    self.apply_anchor_deltas_for_tx(&tx_ref.tx, auth_inputs, &mut journal);
                }
            }

            let block_journal = journal.into_block_journal();
            let event_sequence = self.next_event_sequence;
            let chain_index = self.applied_chain_order.len() as u64;
            let new_events = self.events[old_event_len..].to_vec();
            let state_hash = self
                .commit_applied_block_to_store(accepting_block_hash, &block_journal, chain_index, event_sequence, &new_events)?
                .unwrap_or_else(|| self.compute_state_hash());
            self.block_journals.insert(accepting_block_hash, block_journal);
            self.state_hash_by_block.insert(accepting_block_hash, state_hash);
            self.event_sequence_by_block.insert(accepting_block_hash, event_sequence);
            self.applied_chain_order.push(accepting_block_hash);
            if should_log_long_replay && last_replay_log.elapsed() >= LONG_ATOMIC_REPLAY_LOG_INTERVAL {
                info!("[{IDENT}] Cryptix Atomic virtual-chain apply progress: {}/{} block(s)", idx.saturating_add(1), added_total);
                last_replay_log = Instant::now();
            }
        }

        self.live_correct = !self.degraded;
        if should_log_long_replay {
            info!(
                "[{IDENT}] Cryptix Atomic virtual-chain update applied: +{} / -{} block(s), live_correct={}",
                added_total, removed_total, self.live_correct
            );
        }
        Ok(())
    }

    pub fn prune_history(&mut self, max_retained_blocks: usize) -> bool {
        self.prune_history_with_details(max_retained_blocks).map(|result| result.pruned_processed_ops).unwrap_or(false)
    }

    pub fn prune_history_with_details(&mut self, max_retained_blocks: usize) -> Option<AtomicTokenPruneResult> {
        if max_retained_blocks == 0 {
            return None;
        }
        if self.applied_chain_order.len() <= max_retained_blocks {
            return None;
        }

        let prune_len = self.applied_chain_order.len().saturating_sub(max_retained_blocks);
        let pruned_hashes: Vec<BlockHash> = self.applied_chain_order.drain(..prune_len).collect();
        let pruned_hashes_set = pruned_hashes.iter().copied().collect::<HashSet<_>>();
        let last_pruned_event_sequence =
            pruned_hashes.iter().filter_map(|block_hash| self.event_sequence_by_block.get(block_hash).copied()).max();
        let pruned_processed_op_txids = pruned_hashes
            .iter()
            .filter_map(|block_hash| self.block_journals.get(block_hash))
            .flat_map(|journal| journal.added_processed_ops.iter().copied())
            .collect::<Vec<_>>();

        for block_hash in pruned_hashes.iter().copied() {
            self.block_journals.remove(&block_hash);
            self.state_hash_by_block.remove(&block_hash);
            self.event_sequence_by_block.remove(&block_hash);
        }

        let processed_ops_before = self.processed_ops.len();
        self.processed_ops.retain(|_, op| !pruned_hashes_set.contains(&op.accepting_block_hash));
        let pruned_processed_ops = self.processed_ops.len() != processed_ops_before || !pruned_processed_op_txids.is_empty();

        if let Some(last_pruned_event_sequence) = last_pruned_event_sequence {
            self.events.retain(|event| event.sequence > last_pruned_event_sequence);
            self.rebuild_event_id_index();
        }

        Some(AtomicTokenPruneResult { pruned_hashes, pruned_processed_op_txids, last_pruned_event_sequence, pruned_processed_ops })
    }

    pub fn recompute_state_hashes_for_retained_segment(
        &self,
        retained_segment: &[BlockHash],
    ) -> AtomicTokenResult<HashMap<BlockHash, [u8; 32]>> {
        if retained_segment.is_empty() {
            return Ok(HashMap::new());
        }

        let segment_start = self.applied_chain_order.iter().position(|hash| *hash == retained_segment[0]).ok_or_else(|| {
            AtomicTokenError::Processing(
                "failed refreshing retained state hash cache: requested segment start is not in applied chain".to_string(),
            )
        })?;
        let segment_end =
            self.applied_chain_order.iter().position(|hash| *hash == *retained_segment.last().unwrap()).ok_or_else(|| {
                AtomicTokenError::Processing(
                    "failed refreshing retained state hash cache: requested segment end is not in applied chain".to_string(),
                )
            })?;
        if segment_end < segment_start {
            return Err(AtomicTokenError::Processing(
                "failed refreshing retained state hash cache: requested segment end appears before start".to_string(),
            ));
        }
        if &self.applied_chain_order[segment_start..=segment_end] != retained_segment {
            return Err(AtomicTokenError::Processing(
                "failed refreshing retained state hash cache: requested blocks are not a contiguous retained chain segment"
                    .to_string(),
            ));
        }

        let mut cursor = self.clone();
        for block_hash in self.applied_chain_order[segment_end + 1..].iter().rev().copied() {
            cursor.rollback_block_internal(block_hash, false).map_err(|_| {
                AtomicTokenError::Processing(format!(
                    "failed refreshing retained state hash cache: missing journal while rolling back post-segment block `{block_hash}`"
                ))
            })?;
        }

        let mut refreshed = HashMap::with_capacity(retained_segment.len());
        let should_log_progress = retained_segment.len() >= 1024;
        let mut last_log = Instant::now();
        for (idx, block_hash) in retained_segment.iter().rev().copied().enumerate() {
            refreshed.insert(block_hash, cursor.compute_state_hash());
            cursor.rollback_block_internal(block_hash, false).map_err(|_| {
                AtomicTokenError::Processing(format!(
                    "failed refreshing retained state hash cache: missing journal while rolling back block `{block_hash}`"
                ))
            })?;
            if should_log_progress && last_log.elapsed() >= LONG_ATOMIC_REPLAY_LOG_INTERVAL {
                info!(
                    "[{IDENT}] refreshed retained Atomic state hash cache progress: {}/{} block(s)",
                    idx.saturating_add(1),
                    retained_segment.len()
                );
                last_log = Instant::now();
            }
        }
        Ok(refreshed)
    }

    pub fn recompute_state_hashes_for_retained_segment_from_current_store(
        &mut self,
        retained_segment: &[BlockHash],
    ) -> AtomicTokenResult<HashMap<BlockHash, [u8; 32]>> {
        if retained_segment.is_empty() {
            return Ok(HashMap::new());
        }
        if self.state_store.is_none() {
            return Err(AtomicTokenError::Processing(
                "failed refreshing retained state hash cache: no persistent V2 state store is attached".to_string(),
            ));
        }

        let segment_start = self.applied_chain_order.iter().position(|hash| *hash == retained_segment[0]).ok_or_else(|| {
            AtomicTokenError::Processing(
                "failed refreshing retained state hash cache: requested segment start is not in applied chain".to_string(),
            )
        })?;
        let segment_end =
            self.applied_chain_order.iter().position(|hash| *hash == *retained_segment.last().unwrap()).ok_or_else(|| {
                AtomicTokenError::Processing(
                    "failed refreshing retained state hash cache: requested segment end is not in applied chain".to_string(),
                )
            })?;
        if segment_end < segment_start {
            return Err(AtomicTokenError::Processing(
                "failed refreshing retained state hash cache: requested segment end appears before start".to_string(),
            ));
        }
        if &self.applied_chain_order[segment_start..=segment_end] != retained_segment {
            return Err(AtomicTokenError::Processing(
                "failed refreshing retained state hash cache: requested blocks are not a contiguous retained chain segment"
                    .to_string(),
            ));
        }

        let post_segment_blocks = self.applied_chain_order[segment_end + 1..].to_vec();
        for block_hash in post_segment_blocks.into_iter().rev() {
            let journal = self.rollback_block_internal(block_hash, false).map_err(|_| {
                AtomicTokenError::Processing(format!(
                    "failed refreshing retained state hash cache: missing journal while rolling back post-segment block `{block_hash}`"
                ))
            })?;
            self.commit_rollback_to_store(block_hash, &journal, &[])?;
        }

        let mut refreshed = HashMap::with_capacity(retained_segment.len());
        let should_log_progress = retained_segment.len() >= 1024;
        let mut last_log = Instant::now();
        for (idx, block_hash) in retained_segment.iter().rev().copied().enumerate() {
            let root = self.state_store.as_ref().and_then(|store| store.current_root().ok().flatten()).ok_or_else(|| {
                AtomicTokenError::Processing(
                    "failed refreshing retained state hash cache: persistent V2 state store has no current root".to_string(),
                )
            })?;
            refreshed.insert(block_hash, root);

            let journal = self.rollback_block_internal(block_hash, false).map_err(|_| {
                AtomicTokenError::Processing(format!(
                    "failed refreshing retained state hash cache: missing journal while rolling back block `{block_hash}`"
                ))
            })?;
            self.commit_rollback_to_store(block_hash, &journal, &[])?;
            if should_log_progress && last_log.elapsed() >= LONG_ATOMIC_REPLAY_LOG_INTERVAL {
                info!(
                    "[{IDENT}] refreshed retained Atomic state hash cache from V2 store progress: {}/{} block(s)",
                    idx.saturating_add(1),
                    retained_segment.len()
                );
                last_log = Instant::now();
            }
        }
        Ok(refreshed)
    }

    pub fn refresh_retained_state_hashes_from_current_state(&mut self) -> AtomicTokenResult<usize> {
        let first_replayable = self.first_replayable_block_hash().ok_or_else(|| {
            AtomicTokenError::Processing(
                "failed refreshing retained state hash cache: no contiguous retained replay journal window is available".to_string(),
            )
        })?;
        let suffix_start = self.applied_chain_order.iter().position(|hash| *hash == first_replayable).ok_or_else(|| {
            AtomicTokenError::Processing(
                "failed refreshing retained state hash cache: replay window root is not in applied chain".to_string(),
            )
        })?;
        let retained_suffix = self.applied_chain_order[suffix_start..].to_vec();
        let refreshed = self.recompute_state_hashes_for_retained_segment(&retained_suffix)?;
        for (block_hash, state_hash) in refreshed {
            self.state_hash_by_block.insert(block_hash, state_hash);
        }
        Ok(retained_suffix.len())
    }

    fn rollback_block(&mut self, block_hash: BlockHash) -> Result<BlockJournal, ()> {
        self.rollback_block_internal(block_hash, true)
    }

    fn rollback_block_internal(&mut self, block_hash: BlockHash, emit_reorg_events: bool) -> Result<BlockJournal, ()> {
        let journal = self.block_journals.remove(&block_hash).ok_or(())?;

        for change in journal.changed_assets.iter().rev() {
            match &change.old_value {
                Some(asset) => {
                    self.set_asset_state(change.asset_id, asset.clone());
                }
                None => {
                    self.remove_asset_state(change.asset_id);
                }
            }
        }
        self.rebuild_liquidity_vault_outpoint_index();
        self.rebuild_known_owner_address_cache();

        for change in journal.changed_balances.iter().rev() {
            match change.old_value {
                Some(value) => {
                    self.set_balance_amount(change.key, value);
                }
                None => {
                    self.remove_balance(change.key);
                }
            }
        }

        for change in journal.changed_nonces.iter().rev() {
            match change.old_value {
                Some(value) => {
                    self.set_nonce_value(change.key, value);
                }
                None => {
                    self.remove_nonce_value(change.key);
                }
            }
        }

        for change in journal.changed_anchor_counts.iter().rev() {
            match change.old_value {
                Some(value) => {
                    self.set_anchor_count_value(change.owner_id, value);
                }
                None => {
                    self.remove_anchor_count_value(change.owner_id);
                }
            }
        }

        for txid in journal.added_processed_ops.iter().copied() {
            self.remove_processed_op_value(txid);
        }

        if emit_reorg_events {
            for result in journal.tx_results.iter().rev() {
                self.push_event(TokenEvent {
                    event_id: self.compute_event_id(
                        block_hash,
                        result.txid,
                        EventType::Reorged,
                        result.apply_status,
                        result.noop_reason,
                        result.ordinal,
                    ),
                    sequence: 0,
                    accepting_block_hash: block_hash,
                    txid: result.txid,
                    event_type: EventType::Reorged,
                    apply_status: result.apply_status,
                    noop_reason: result.noop_reason,
                    ordinal: result.ordinal,
                    reorg_of_event_id: Some(result.event_id),
                    details: result.details.clone(),
                });
            }
        } else {
            self.remove_events_for_rolled_back_results(&journal.tx_results);
        }

        self.state_hash_by_block.remove(&block_hash);
        self.event_sequence_by_block.remove(&block_hash);
        while self.applied_chain_order.last() == Some(&block_hash) {
            self.applied_chain_order.pop();
        }
        self.applied_chain_order.retain(|h| *h != block_hash);
        Ok(journal)
    }

    fn remove_events_for_rolled_back_results(&mut self, tx_results: &[TokenApplyResult]) {
        if tx_results.is_empty() {
            return;
        }

        let removed_event_ids: HashSet<[u8; 32]> = tx_results.iter().map(|result| result.event_id).collect();
        self.events.retain(|event| !removed_event_ids.contains(&event.event_id));
        self.next_event_sequence = self.events.last().map(|event| event.sequence).unwrap_or(0);
        self.rebuild_event_id_index();
    }

    async fn flatten_acceptance_for_block(
        &self,
        accepting_block_hash: BlockHash,
        acceptance_data: &AcceptanceData,
        session: &ConsensusProxy,
    ) -> AtomicTokenResult<NormalizedAcceptance> {
        let mut block_cache: HashMap<BlockHash, (Arc<Vec<Transaction>>, u64, u64)> = HashMap::new();
        let mut refs: Vec<CanonicalTxRef> = Vec::new();

        for (acceptance_entry_position, mergeset_entry) in acceptance_data.iter().enumerate() {
            let (txs, source_block_daa_score, source_block_time) =
                if let Some((txs, daa_score, timestamp)) = block_cache.get(&mergeset_entry.block_hash) {
                    (txs.clone(), *daa_score, *timestamp)
                } else {
                    let block = session.async_get_block(mergeset_entry.block_hash).await?;
                    let daa_score = block.header.daa_score;
                    let timestamp = block.header.timestamp;
                    let txs = block.transactions;
                    block_cache.insert(mergeset_entry.block_hash, (txs.clone(), daa_score, timestamp));
                    (txs, daa_score, timestamp)
                };

            for accepted_tx in mergeset_entry.accepted_transactions.iter() {
                let tx_index = accepted_tx.index_within_block as usize;
                if tx_index >= txs.len() {
                    return Err(AtomicTokenError::Processing(format!(
                        "malformed acceptance data: tx index `{}` out of range",
                        accepted_tx.index_within_block
                    )));
                }

                let tx = txs[tx_index].clone();
                if tx.id() != accepted_tx.transaction_id {
                    return Err(AtomicTokenError::Processing(
                        "malformed acceptance data: tx id mismatch at index_within_block".to_string(),
                    ));
                }

                refs.push(CanonicalTxRef {
                    txid: accepted_tx.transaction_id,
                    source_block_hash: mergeset_entry.block_hash,
                    source_block_daa_score,
                    source_block_time,
                    tx_index: accepted_tx.index_within_block,
                    acceptance_entry_position: acceptance_entry_position as u32,
                    tx,
                });
            }
        }
        normalize_acceptance_refs(accepting_block_hash, refs)
    }

    fn apply_transaction(
        &mut self,
        accepting_block_hash: BlockHash,
        accepting_block_daa_score: u64,
        _accepting_block_time: u64,
        tx_ref: &CanonicalTxRef,
        ordinal: u32,
        auth_inputs: &HashMap<TransactionOutpoint, UtxoEntry>,
        journal: &mut JournalBuilder,
    ) -> bool {
        let tx = &tx_ref.tx;
        if tx.is_coinbase() {
            return false;
        }
        if accepting_block_daa_score < self.payload_hf_activation_daa_score {
            return true;
        }
        if !tx.subnetwork_id.is_payload() || tx.payload.is_empty() {
            return true;
        }

        let parsed = match parse_atomic_token_payload(&tx.payload) {
            Some(value) => value,
            None => return true,
        };

        let existing_processed_op = match self.processed_op_value_strict(&tx.id()) {
            Ok(value) => value,
            Err(err) => {
                warn!(
                    "[{IDENT}] failed reading persisted duplicate CAT replay guard; marking degraded and suppressing replay: txid={}, accepting_block={}, source_block={}, tx_index={}, error={}",
                    tx.id(),
                    accepting_block_hash,
                    tx_ref.source_block_hash,
                    tx_ref.tx_index,
                    err
                );
                self.mark_degraded();
                return false;
            }
        };

        if let Some(existing) = existing_processed_op {
            warn!(
                "[{IDENT}] duplicate accepted CAT transaction suppressed during Atomic replay: txid={}, original_accepting_block={}, duplicate_accepting_block={}, duplicate_source_block={}, duplicate_tx_index={}; token op and anchor deltas were not applied again",
                tx.id(),
                existing.accepting_block_hash,
                accepting_block_hash,
                tx_ref.source_block_hash,
                tx_ref.tx_index
            );
            return false;
        }

        match parsed {
            Ok(parsed) => {
                let result = self.execute_parsed_op(
                    tx,
                    &parsed,
                    auth_inputs,
                    tx_ref.source_block_hash,
                    tx_ref.source_block_daa_score,
                    tx_ref.source_block_time,
                    journal,
                );
                match result {
                    Ok(details) => self.insert_processed(
                        tx.id(),
                        accepting_block_hash,
                        ApplyStatus::Applied,
                        NoopReason::None,
                        tx_ref.source_block_hash,
                        ordinal,
                        details,
                        journal,
                    ),
                    Err(noop_reason) => {
                        let replay_integrity_failure = is_replay_integrity_failure(noop_reason);
                        if replay_integrity_failure {
                            warn!(
                                "[{IDENT}] accepted CAT transaction failed Atomic replay integrity; marking degraded: txid={}, accepting_block={}, op={:?}, nonce={}, reason={:?}",
                                tx.id(),
                                accepting_block_hash,
                                parsed.header.op,
                                parsed.header.nonce,
                                noop_reason
                            );
                            self.mark_degraded();
                        }
                        let details = self.build_event_details(tx, &parsed, auth_inputs);
                        self.insert_processed(
                            tx.id(),
                            accepting_block_hash,
                            ApplyStatus::Noop,
                            if replay_integrity_failure { NoopReason::InternalMalformedAcceptance } else { noop_reason },
                            tx_ref.source_block_hash,
                            ordinal,
                            details,
                            journal,
                        );
                    }
                }
            }
            Err(noop_reason) => {
                // Accepted CAT payload parse failures are consensus/index divergence.
                // We preserve journal continuity but force degraded runtime state.
                warn!(
                    "[{IDENT}] accepted CAT transaction failed Atomic payload parsing; marking degraded: txid={}, accepting_block={}, reason={:?}",
                    tx.id(),
                    accepting_block_hash,
                    noop_reason
                );
                self.mark_degraded();
                self.insert_processed(
                    tx.id(),
                    accepting_block_hash,
                    ApplyStatus::Noop,
                    NoopReason::InternalMalformedAcceptance,
                    tx_ref.source_block_hash,
                    ordinal,
                    TokenEventDetails::default(),
                    journal,
                );
            }
        }
        true
    }

    fn execute_parsed_op(
        &mut self,
        tx: &Transaction,
        parsed: &ParsedTokenPayload,
        auth_inputs: &HashMap<TransactionOutpoint, UtxoEntry>,
        source_block_hash: BlockHash,
        source_block_daa_score: u64,
        source_block_time: u64,
        journal: &mut JournalBuilder,
    ) -> Result<TokenEventDetails, NoopReason> {
        let spent_vault_inputs = self.collect_spent_liquidity_vault_inputs(tx, auth_inputs)?;
        let liquidity_vault_output_count = tx
            .outputs
            .iter()
            .filter(|output| matches!(ScriptClass::from_script(&output.script_public_key), ScriptClass::LiquidityVault))
            .count();
        let auth_context = self.resolve_auth_context(tx, parsed.header.auth_input_index, auth_inputs)?;
        let owner_id = auth_context.owner_id;
        self.remember_owner_address(owner_id, auth_context.address_version, auth_context.address_payload.as_slice());
        let nonce_key = nonce_key_for_op(owner_id, &parsed.op);
        let expected_nonce = self.nonce_value(&nonce_key);
        if parsed.header.nonce != expected_nonce {
            return Err(NoopReason::BadNonce);
        }
        let next_nonce = expected_nonce.checked_add(1).ok_or(NoopReason::InternalMalformedAcceptance)?;
        if !spent_vault_inputs.is_empty() {
            match &parsed.op {
                TokenOp::BuyLiquidityExactIn(_) | TokenOp::SellLiquidityExactIn(_) | TokenOp::ClaimLiquidityFees(_) => {}
                _ => return Err(NoopReason::VaultInputCount),
            }
        }
        if matches!(parsed.op, TokenOp::CreateLiquidityAsset(_)) && !spent_vault_inputs.is_empty() {
            return Err(NoopReason::VaultInputCount);
        }
        if liquidity_vault_output_count > 0 && !token_op_allows_liquidity_vault_output(&parsed.op) {
            return Err(NoopReason::VaultOutputCount);
        }
        self.validate_replacement_anchor(tx, &auth_context, auth_inputs)?;

        let mut details = self.build_event_details(tx, parsed, auth_inputs);
        match &parsed.op {
            TokenOp::CreateAsset(op) => self.execute_create_asset(
                tx.id().as_bytes(),
                owner_id,
                op,
                source_block_hash,
                source_block_daa_score,
                source_block_time,
                journal,
            )?,
            TokenOp::CreateAssetWithMint(op) => self.execute_create_asset_with_mint(
                tx.id().as_bytes(),
                owner_id,
                op,
                source_block_hash,
                source_block_daa_score,
                source_block_time,
                journal,
            )?,
            TokenOp::CreateLiquidityAsset(op) => {
                let token_out = self.execute_create_liquidity_asset(
                    tx,
                    &auth_context,
                    op,
                    source_block_hash,
                    source_block_daa_score,
                    source_block_time,
                    journal,
                )?;
                details.to_owner_id = (token_out > 0).then_some(owner_id);
                details.amount = (token_out > 0).then_some(token_out);
            }
            TokenOp::Transfer(op) => self.execute_transfer(owner_id, op.asset_id, op.to_owner_id, op.amount, journal)?,
            TokenOp::Mint(op) => self.execute_mint(owner_id, op, journal)?,
            TokenOp::Burn(op) => self.execute_burn(owner_id, op.asset_id, op.amount, journal)?,
            TokenOp::BuyLiquidityExactIn(op) => {
                let token_out = self.execute_buy_liquidity(tx, &auth_context, op, auth_inputs, journal)?;
                details.amount = Some(token_out);
            }
            TokenOp::SellLiquidityExactIn(op) => self.execute_sell_liquidity(tx, owner_id, op, auth_inputs, journal)?,
            TokenOp::ClaimLiquidityFees(op) => self.execute_claim_liquidity_fees(tx, owner_id, op, auth_inputs, journal)?,
        }

        self.record_nonce_before(nonce_key, journal);
        self.set_nonce_value(nonce_key, next_nonce);
        Ok(details)
    }

    fn validate_replacement_anchor(
        &self,
        tx: &Transaction,
        auth_context: &AuthContext,
        auth_inputs: &HashMap<TransactionOutpoint, UtxoEntry>,
    ) -> Result<(), NoopReason> {
        let owner_id = auth_context.owner_id;
        let before_count = self.anchor_count_value(&owner_id);
        let mut spent_for_owner = 0u64;
        for input in tx.inputs.iter() {
            if let Some(entry) = auth_inputs.get(&input.previous_outpoint) {
                if self.owner_id_from_script_if_whitelisted(&entry.script_public_key) == Some(owner_id) {
                    spent_for_owner = spent_for_owner.saturating_add(1);
                }
            }
        }

        if before_count.saturating_sub(spent_for_owner) > 0 {
            return Ok(());
        }

        let has_replacement_anchor =
            tx.outputs.iter().any(|output| self.owner_id_from_script_if_whitelisted(&output.script_public_key) == Some(owner_id));
        if has_replacement_anchor {
            Ok(())
        } else {
            Err(NoopReason::BadAuthInput)
        }
    }

    fn apply_anchor_deltas_for_tx(
        &mut self,
        tx: &Transaction,
        auth_inputs: &HashMap<TransactionOutpoint, UtxoEntry>,
        journal: &mut JournalBuilder,
    ) {
        let mut spent_counts: HashMap<[u8; 32], u64> = HashMap::new();
        for input in tx.inputs.iter() {
            let Some(entry) = auth_inputs.get(&input.previous_outpoint) else {
                continue;
            };
            let Some(owner_id) = self.owner_id_from_script_if_whitelisted(&entry.script_public_key) else {
                continue;
            };
            *spent_counts.entry(owner_id).or_insert(0) += 1;
        }

        let mut created_counts: HashMap<[u8; 32], u64> = HashMap::new();
        for output in tx.outputs.iter() {
            let Some(owner_id) = self.owner_id_from_script_if_whitelisted(&output.script_public_key) else {
                continue;
            };
            *created_counts.entry(owner_id).or_insert(0) += 1;
        }

        let owners: HashSet<[u8; 32]> = spent_counts.keys().copied().chain(created_counts.keys().copied()).collect();
        for owner_id in owners {
            let old_count = self.anchor_count_value(&owner_id);
            let spent = spent_counts.get(&owner_id).copied().unwrap_or(0);
            let created = created_counts.get(&owner_id).copied().unwrap_or(0);
            let new_count = old_count.saturating_sub(spent).saturating_add(created);
            if new_count == old_count {
                continue;
            }

            self.record_anchor_count_before(owner_id, journal);
            if new_count == 0 {
                self.remove_anchor_count_value(owner_id);
            } else {
                self.set_anchor_count_value(owner_id, new_count);
            }
        }
    }

    fn execute_create_asset(
        &mut self,
        txid_bytes: [u8; 32],
        creator_owner_id: [u8; 32],
        op: &CreateAssetOp,
        source_block_hash: BlockHash,
        source_block_daa_score: u64,
        source_block_time: u64,
        journal: &mut JournalBuilder,
    ) -> Result<(), NoopReason> {
        if self.asset_value(&txid_bytes).is_some() {
            return Err(NoopReason::AssetAlreadyExists);
        }

        if op.token_version != CURRENT_TOKEN_VERSION {
            return Err(NoopReason::BadTokenVersion);
        }

        if op.decimals > crate::payload::MAX_DECIMALS {
            return Err(NoopReason::BadDecimals);
        }

        match op.supply_mode {
            SupplyMode::Capped if op.max_supply == 0 => return Err(NoopReason::BadMaxSupply),
            SupplyMode::Uncapped if op.max_supply != 0 => return Err(NoopReason::BadMaxSupply),
            _ => {}
        }

        self.record_asset_before(txid_bytes, journal);
        self.set_asset_state(
            txid_bytes,
            TokenAsset {
                asset_id: txid_bytes,
                creator_owner_id,
                asset_class: TokenAssetClass::Standard,
                token_version: op.token_version,
                mint_authority_owner_id: op.mint_authority_owner_id,
                decimals: op.decimals,
                supply_mode: op.supply_mode,
                max_supply: op.max_supply,
                total_supply: 0,
                name: op.name.clone(),
                symbol: op.symbol.clone(),
                metadata: op.metadata.clone(),
                platform_tag: op.platform_tag.clone(),
                created_block_hash: Some(source_block_hash),
                created_daa_score: Some(source_block_daa_score),
                created_at: Some(source_block_time),
                liquidity: None,
            },
        );
        Ok(())
    }

    fn execute_create_asset_with_mint(
        &mut self,
        txid_bytes: [u8; 32],
        creator_owner_id: [u8; 32],
        op: &CreateAssetWithMintOp,
        source_block_hash: BlockHash,
        source_block_daa_score: u64,
        source_block_time: u64,
        journal: &mut JournalBuilder,
    ) -> Result<(), NoopReason> {
        if self.asset_value(&txid_bytes).is_some() {
            return Err(NoopReason::AssetAlreadyExists);
        }
        if op.token_version != CURRENT_TOKEN_VERSION {
            return Err(NoopReason::BadTokenVersion);
        }
        if op.decimals > crate::payload::MAX_DECIMALS {
            return Err(NoopReason::BadDecimals);
        }
        match op.supply_mode {
            SupplyMode::Capped if op.max_supply == 0 => return Err(NoopReason::BadMaxSupply),
            SupplyMode::Uncapped if op.max_supply != 0 => return Err(NoopReason::BadMaxSupply),
            _ => {}
        }

        let mut total_supply = 0u128;
        let mut initial_mint_balance: Option<(BalanceKey, u128)> = None;
        if op.initial_mint_amount > 0 {
            if matches!(op.supply_mode, SupplyMode::Capped) && op.initial_mint_amount > op.max_supply {
                return Err(NoopReason::SupplyCapExceeded);
            }
            let receiver_key = BalanceKey { asset_id: txid_bytes, owner_id: op.initial_mint_to_owner_id };
            let receiver_balance = self.balance_value(&receiver_key);
            let receiver_after = receiver_balance.checked_add(op.initial_mint_amount).ok_or(NoopReason::BalanceOverflow)?;
            total_supply = op.initial_mint_amount;
            initial_mint_balance = Some((receiver_key, receiver_after));
        }

        self.record_asset_before(txid_bytes, journal);
        self.set_asset_state(
            txid_bytes,
            TokenAsset {
                asset_id: txid_bytes,
                creator_owner_id,
                asset_class: TokenAssetClass::Standard,
                token_version: op.token_version,
                mint_authority_owner_id: op.mint_authority_owner_id,
                decimals: op.decimals,
                supply_mode: op.supply_mode,
                max_supply: op.max_supply,
                total_supply,
                name: op.name.clone(),
                symbol: op.symbol.clone(),
                metadata: op.metadata.clone(),
                platform_tag: op.platform_tag.clone(),
                created_block_hash: Some(source_block_hash),
                created_daa_score: Some(source_block_daa_score),
                created_at: Some(source_block_time),
                liquidity: None,
            },
        );
        if let Some((receiver_key, receiver_after)) = initial_mint_balance {
            self.record_balance_before(receiver_key, journal);
            self.set_balance_amount(receiver_key, receiver_after);
        }
        Ok(())
    }

    fn execute_transfer(
        &mut self,
        from_owner_id: [u8; 32],
        asset_id: [u8; 32],
        to_owner_id: [u8; 32],
        amount: u128,
        journal: &mut JournalBuilder,
    ) -> Result<(), NoopReason> {
        if amount == 0 {
            return Err(NoopReason::InvalidAmount);
        }

        let mut asset = self.asset_value(&asset_id).ok_or(NoopReason::AssetNotFound)?;
        let is_liquidity_asset = matches!(asset.asset_class, TokenAssetClass::Liquidity);
        if is_liquidity_asset {
            self.validate_liquidity_invariants(&asset)?;
        }

        let from_key = BalanceKey { asset_id, owner_id: from_owner_id };
        let to_key = BalanceKey { asset_id, owner_id: to_owner_id };

        if from_key == to_key {
            // Self-transfers are valid nonce-bearing ops but must not mutate balances.
            let sender_balance = self.balance_value(&from_key);
            sender_balance.checked_sub(amount).ok_or(NoopReason::InsufficientBalance)?;
            return Ok(());
        }

        let sender_balance = self.balance_value(&from_key);
        let receiver_balance = self.balance_value(&to_key);

        let sender_after = sender_balance.checked_sub(amount).ok_or(NoopReason::InsufficientBalance)?;
        let receiver_after = receiver_balance.checked_add(amount).ok_or(NoopReason::BalanceOverflow)?;

        self.record_balance_before(from_key, journal);
        self.record_balance_before(to_key, journal);

        self.set_balance_amount(from_key, sender_after);
        self.set_balance_amount(to_key, receiver_after);
        if is_liquidity_asset {
            let mut asset_changed = false;
            if let Some(pool) = asset.liquidity.as_mut() {
                if sender_after == 0 && pool.holder_addresses.remove(&from_owner_id).is_some() {
                    asset_changed = true;
                }
            }
            if asset_changed {
                self.record_asset_before(asset_id, journal);
                self.set_asset_state(asset_id, asset);
            }
        }
        Ok(())
    }

    fn execute_mint(&mut self, sender_owner_id: [u8; 32], op: &MintOp, journal: &mut JournalBuilder) -> Result<(), NoopReason> {
        if op.amount == 0 {
            return Err(NoopReason::InvalidAmount);
        }

        let mut asset = self.asset_value(&op.asset_id).ok_or(NoopReason::AssetNotFound)?;
        if matches!(asset.asset_class, TokenAssetClass::Liquidity) {
            return Err(NoopReason::LegacyOpForLiquidityAsset);
        }
        if asset.mint_authority_owner_id != sender_owner_id {
            return Err(NoopReason::UnauthorizedMint);
        }

        let new_total_supply = asset.total_supply.checked_add(op.amount).ok_or(NoopReason::SupplyOverflow)?;
        if matches!(asset.supply_mode, SupplyMode::Capped) && new_total_supply > asset.max_supply {
            return Err(NoopReason::SupplyCapExceeded);
        }

        let receiver_key = BalanceKey { asset_id: op.asset_id, owner_id: op.to_owner_id };
        let receiver_balance = self.balance_value(&receiver_key);
        let receiver_after = receiver_balance.checked_add(op.amount).ok_or(NoopReason::BalanceOverflow)?;

        self.record_asset_before(op.asset_id, journal);
        self.record_balance_before(receiver_key, journal);

        asset.total_supply = new_total_supply;
        self.set_asset_state(op.asset_id, asset);
        self.set_balance_amount(receiver_key, receiver_after);
        Ok(())
    }

    fn execute_burn(
        &mut self,
        sender_owner_id: [u8; 32],
        asset_id: [u8; 32],
        amount: u128,
        journal: &mut JournalBuilder,
    ) -> Result<(), NoopReason> {
        if amount == 0 {
            return Err(NoopReason::InvalidAmount);
        }

        let mut asset = self.asset_value(&asset_id).ok_or(NoopReason::AssetNotFound)?;
        if matches!(asset.asset_class, TokenAssetClass::Liquidity) {
            return Err(NoopReason::LegacyOpForLiquidityAsset);
        }
        let sender_key = BalanceKey { asset_id, owner_id: sender_owner_id };
        let sender_balance = self.balance_value(&sender_key);

        let sender_after = sender_balance.checked_sub(amount).ok_or(NoopReason::InsufficientBalance)?;
        let supply_after = asset.total_supply.checked_sub(amount).ok_or(NoopReason::SupplyUnderflow)?;

        self.record_asset_before(asset_id, journal);
        self.record_balance_before(sender_key, journal);

        asset.total_supply = supply_after;
        self.set_asset_state(asset_id, asset);
        self.set_balance_amount(sender_key, sender_after);
        Ok(())
    }

    fn execute_create_liquidity_asset(
        &mut self,
        tx: &Transaction,
        creator_auth: &AuthContext,
        op: &CreateLiquidityAssetOp,
        source_block_hash: BlockHash,
        source_block_daa_score: u64,
        source_block_time: u64,
        journal: &mut JournalBuilder,
    ) -> Result<u128, NoopReason> {
        let creator_owner_id = creator_auth.owner_id;
        let asset_id = tx.id().as_bytes();
        if self.asset_value(&asset_id).is_some() {
            return Err(NoopReason::AssetAlreadyExists);
        }
        if op.token_version != CURRENT_TOKEN_VERSION {
            return Err(NoopReason::BadTokenVersion);
        }
        if op.curve_version != CURRENT_LIQUIDITY_CURVE_VERSION {
            return Err(NoopReason::BadLiquidityCurveVersion);
        }
        validate_liquidity_curve_mode(op.curve_mode).map_err(|_| NoopReason::BadLiquidityCurveMode)?;
        validate_liquidity_curve_parameters(
            op.curve_mode,
            op.individual_virtual_cpay_reserves_sompi,
            op.individual_virtual_token_multiplier_bps,
        )
        .map_err(|_| NoopReason::BadLiquidityCurveMode)?;
        if op.decimals != LIQUIDITY_TOKEN_DECIMALS {
            return Err(NoopReason::BadDecimals);
        }
        if !(MIN_LIQUIDITY_SUPPLY_RAW..=MAX_LIQUIDITY_SUPPLY_RAW).contains(&op.max_supply) {
            return Err(NoopReason::BadMaxSupply);
        }
        if op.seed_reserve_sompi != MIN_LIQUIDITY_SEED_RESERVE_SOMPI {
            return Err(NoopReason::InvalidAmount);
        }
        validate_liquidity_unlock_target(op.liquidity_unlock_target_sompi)?;

        let (vault_output_index, vault_output_value) = self.resolve_create_liquidity_vault_output(tx)?;
        let expected_vault_value = op.seed_reserve_sompi.checked_add(op.launch_buy_sompi).ok_or(NoopReason::SupplyOverflow)?;
        if vault_output_value != expected_vault_value {
            return Err(NoopReason::VaultOutpointMismatch);
        }

        let mut fee_recipients = self.build_fee_recipient_state(&op.recipients)?;
        let mut real_cpay_reserves_sompi = INITIAL_REAL_CPAY_RESERVES_SOMPI;
        let mut real_token_reserves = op.max_supply;
        let mut virtual_cpay_reserves_sompi =
            initial_virtual_cpay_reserves_sompi_for_curve(op.curve_mode, op.individual_virtual_cpay_reserves_sompi)
                .map_err(|_| NoopReason::BadLiquidityCurveMode)?;
        let mut virtual_token_reserves =
            initial_virtual_token_reserves_for_curve(op.max_supply, op.curve_mode, op.individual_virtual_token_multiplier_bps)
                .map_err(|_| NoopReason::BadMaxSupply)?;
        let mut unclaimed_fee_total_sompi = 0u64;
        let mut total_supply = 0u128;
        let mut holder_addresses: HashMap<[u8; 32], LiquidityHolderAddressState> = HashMap::new();
        let mut launch_receiver_after: Option<(BalanceKey, u128)> = None;

        if op.launch_buy_sompi > 0 {
            let fee_trade = calculate_trade_fee(op.launch_buy_sompi, op.fee_bps).map_err(map_liquidity_math_error)?;
            let launch_buy_net = op.launch_buy_sompi.checked_sub(fee_trade).ok_or(NoopReason::SupplyUnderflow)?;
            let (token_out, new_real_token_reserves, new_virtual_cpay_reserves_sompi, new_virtual_token_reserves) =
                cpmm_buy(real_token_reserves, virtual_cpay_reserves_sompi, virtual_token_reserves, launch_buy_net)
                    .map_err(map_liquidity_math_error)?;
            if token_out < op.launch_buy_min_token_out {
                return Err(NoopReason::MinOutViolation);
            }
            let canonical_launch_buy = min_gross_input_for_token_out(
                real_token_reserves,
                virtual_cpay_reserves_sompi,
                virtual_token_reserves,
                token_out,
                op.fee_bps,
            )
            .map_err(map_liquidity_math_error)?;
            if op.launch_buy_sompi != canonical_launch_buy {
                return Err(NoopReason::InvalidAmount);
            }
            real_cpay_reserves_sompi = real_cpay_reserves_sompi.checked_add(launch_buy_net).ok_or(NoopReason::SupplyOverflow)?;
            real_token_reserves = new_real_token_reserves;
            virtual_cpay_reserves_sompi = new_virtual_cpay_reserves_sompi;
            virtual_token_reserves = new_virtual_token_reserves;
            self.apply_fee_to_pool(&mut fee_recipients, &mut unclaimed_fee_total_sompi, fee_trade)?;
            total_supply = token_out;

            let receiver_key = BalanceKey { asset_id, owner_id: creator_owner_id };
            let receiver_balance = self.balance_value(&receiver_key);
            let receiver_after = receiver_balance.checked_add(token_out).ok_or(NoopReason::BalanceOverflow)?;
            launch_receiver_after = Some((receiver_key, receiver_after));
            holder_addresses.insert(
                creator_owner_id,
                LiquidityHolderAddressState {
                    address_version: creator_auth.address_version,
                    address_payload: creator_auth.address_payload.clone(),
                },
            );
        }

        self.record_asset_before(asset_id, journal);
        let unlocked = op.liquidity_unlock_target_sompi == 0 || real_cpay_reserves_sompi >= op.liquidity_unlock_target_sompi;
        let asset = TokenAsset {
            asset_id,
            creator_owner_id,
            asset_class: TokenAssetClass::Liquidity,
            token_version: op.token_version,
            mint_authority_owner_id: [0u8; 32],
            decimals: op.decimals,
            supply_mode: SupplyMode::Capped,
            max_supply: op.max_supply,
            total_supply,
            name: op.name.clone(),
            symbol: op.symbol.clone(),
            metadata: op.metadata.clone(),
            platform_tag: op.platform_tag.clone(),
            created_block_hash: Some(source_block_hash),
            created_daa_score: Some(source_block_daa_score),
            created_at: Some(source_block_time),
            liquidity: Some(LiquidityPoolState {
                pool_nonce: 1,
                curve_version: op.curve_version,
                curve_mode: op.curve_mode,
                individual_virtual_cpay_reserves_sompi: op.individual_virtual_cpay_reserves_sompi,
                individual_virtual_token_multiplier_bps: op.individual_virtual_token_multiplier_bps,
                real_cpay_reserves_sompi,
                real_token_reserves,
                virtual_cpay_reserves_sompi,
                virtual_token_reserves,
                unclaimed_fee_total_sompi,
                fee_bps: op.fee_bps,
                fee_recipients,
                vault_outpoint: TransactionOutpoint::new(tx.id(), vault_output_index),
                vault_value_sompi: vault_output_value,
                unlock_target_sompi: op.liquidity_unlock_target_sompi,
                unlocked,
                holder_addresses,
            }),
        };
        self.validate_liquidity_invariants(&asset)?;
        self.set_asset_state(asset_id, asset);
        if let Some((receiver_key, receiver_after)) = launch_receiver_after {
            self.record_balance_before(receiver_key, journal);
            self.set_balance_amount(receiver_key, receiver_after);
        }
        Ok(total_supply)
    }

    fn execute_buy_liquidity(
        &mut self,
        tx: &Transaction,
        buyer_auth: &AuthContext,
        op: &BuyLiquidityExactInOp,
        auth_inputs: &HashMap<TransactionOutpoint, UtxoEntry>,
        journal: &mut JournalBuilder,
    ) -> Result<u128, NoopReason> {
        let buyer_owner_id = buyer_auth.owner_id;
        let mut asset = self.asset_value(&op.asset_id).ok_or(NoopReason::AssetNotFound)?;
        if !matches!(asset.asset_class, TokenAssetClass::Liquidity) {
            return Err(NoopReason::LegacyOpForLiquidityAsset);
        }
        let mut pool = asset.liquidity.clone().ok_or(NoopReason::AssetNotFound)?;
        if pool.pool_nonce != op.expected_pool_nonce {
            return Err(NoopReason::NonceStale);
        }
        let vault_transition = self.resolve_liquidity_vault_transition(tx, auth_inputs, pool.vault_outpoint)?;
        let vault_delta =
            vault_transition.output_value.checked_sub(vault_transition.input_value).ok_or(NoopReason::SupplyUnderflow)?;
        if vault_delta != op.cpay_in_sompi {
            return Err(NoopReason::VaultOutpointMismatch);
        }

        let fee_trade = calculate_trade_fee(op.cpay_in_sompi, pool.fee_bps).map_err(map_liquidity_math_error)?;
        let net_in = op.cpay_in_sompi.checked_sub(fee_trade).ok_or(NoopReason::SupplyUnderflow)?;
        let (token_out, new_real_token_reserves, new_virtual_cpay_reserves_sompi, new_virtual_token_reserves) =
            cpmm_buy(pool.real_token_reserves, pool.virtual_cpay_reserves_sompi, pool.virtual_token_reserves, net_in)
                .map_err(map_liquidity_math_error)?;
        if token_out < op.min_token_out {
            return Err(NoopReason::MinOutViolation);
        }
        let canonical_cpay_in = min_gross_input_for_token_out(
            pool.real_token_reserves,
            pool.virtual_cpay_reserves_sompi,
            pool.virtual_token_reserves,
            token_out,
            pool.fee_bps,
        )
        .map_err(map_liquidity_math_error)?;
        if op.cpay_in_sompi != canonical_cpay_in {
            return Err(NoopReason::InvalidAmount);
        }

        self.record_asset_before(op.asset_id, journal);
        let receiver_key = BalanceKey { asset_id: op.asset_id, owner_id: buyer_owner_id };
        self.record_balance_before(receiver_key, journal);

        pool.real_cpay_reserves_sompi = pool.real_cpay_reserves_sompi.checked_add(net_in).ok_or(NoopReason::SupplyOverflow)?;
        pool.real_token_reserves = new_real_token_reserves;
        pool.virtual_cpay_reserves_sompi = new_virtual_cpay_reserves_sompi;
        pool.virtual_token_reserves = new_virtual_token_reserves;
        if pool.unlock_target_sompi > 0 && pool.real_cpay_reserves_sompi >= pool.unlock_target_sompi {
            pool.unlocked = true;
        }
        self.apply_fee_to_pool(&mut pool.fee_recipients, &mut pool.unclaimed_fee_total_sompi, fee_trade)?;
        pool.vault_outpoint = TransactionOutpoint::new(tx.id(), vault_transition.output_index);
        pool.vault_value_sompi = vault_transition.output_value;
        pool.pool_nonce = pool.pool_nonce.checked_add(1).ok_or(NoopReason::SupplyOverflow)?;
        pool.holder_addresses.insert(
            buyer_owner_id,
            LiquidityHolderAddressState {
                address_version: buyer_auth.address_version,
                address_payload: buyer_auth.address_payload.clone(),
            },
        );

        let receiver_balance = self.balance_value(&receiver_key);
        let receiver_after = receiver_balance.checked_add(token_out).ok_or(NoopReason::BalanceOverflow)?;

        let new_total_supply = asset.total_supply.checked_add(token_out).ok_or(NoopReason::SupplyOverflow)?;
        asset.total_supply = new_total_supply;
        asset.liquidity = Some(pool);
        self.validate_liquidity_invariants(&asset)?;
        self.set_asset_state(op.asset_id, asset);
        self.set_balance_amount(receiver_key, receiver_after);
        Ok(token_out)
    }

    fn execute_sell_liquidity(
        &mut self,
        tx: &Transaction,
        seller_owner_id: [u8; 32],
        op: &SellLiquidityExactInOp,
        auth_inputs: &HashMap<TransactionOutpoint, UtxoEntry>,
        journal: &mut JournalBuilder,
    ) -> Result<(), NoopReason> {
        let mut asset = self.asset_value(&op.asset_id).ok_or(NoopReason::AssetNotFound)?;
        if !matches!(asset.asset_class, TokenAssetClass::Liquidity) {
            return Err(NoopReason::LegacyOpForLiquidityAsset);
        }
        let mut pool = asset.liquidity.clone().ok_or(NoopReason::AssetNotFound)?;
        if pool.pool_nonce != op.expected_pool_nonce {
            return Err(NoopReason::NonceStale);
        }
        if liquidity_sell_locked(&pool) {
            return Err(NoopReason::LiquiditySellLocked);
        }

        let sender_key = BalanceKey { asset_id: op.asset_id, owner_id: seller_owner_id };
        let sender_balance = self.balance_value(&sender_key);
        let sender_after = sender_balance.checked_sub(op.token_in).ok_or(NoopReason::InsufficientBalance)?;
        let supply_after = asset.total_supply.checked_sub(op.token_in).ok_or(NoopReason::SupplyUnderflow)?;

        let (gross_out, new_real_cpay_reserves_sompi, new_virtual_cpay_reserves_sompi, new_virtual_token_reserves) =
            cpmm_sell(pool.real_cpay_reserves_sompi, pool.virtual_cpay_reserves_sompi, pool.virtual_token_reserves, op.token_in)
                .map_err(map_liquidity_math_error)?;
        let fee_trade = calculate_trade_fee(gross_out, pool.fee_bps).map_err(map_liquidity_math_error)?;
        let cpay_out = gross_out.checked_sub(fee_trade).ok_or(NoopReason::SupplyUnderflow)?;
        if cpay_out == 0 {
            return Err(NoopReason::ZeroOutput);
        }
        if cpay_out < op.min_cpay_out_sompi {
            return Err(NoopReason::MinOutViolation);
        }
        if cpay_out < LIQUIDITY_MIN_PAYOUT_SOMPI {
            return Err(NoopReason::InvalidAmount);
        }

        self.validate_payout_output(tx, op.cpay_receive_output_index, cpay_out, None)?;
        let vault_transition = self.resolve_liquidity_vault_transition(tx, auth_inputs, pool.vault_outpoint)?;
        let vault_delta =
            vault_transition.input_value.checked_sub(vault_transition.output_value).ok_or(NoopReason::SupplyUnderflow)?;
        if vault_delta != cpay_out {
            return Err(NoopReason::VaultOutpointMismatch);
        }

        self.record_asset_before(op.asset_id, journal);
        self.record_balance_before(sender_key, journal);

        pool.real_cpay_reserves_sompi = new_real_cpay_reserves_sompi;
        pool.real_token_reserves = pool.real_token_reserves.checked_add(op.token_in).ok_or(NoopReason::SupplyOverflow)?;
        pool.virtual_cpay_reserves_sompi = new_virtual_cpay_reserves_sompi;
        pool.virtual_token_reserves = new_virtual_token_reserves;
        self.apply_fee_to_pool(&mut pool.fee_recipients, &mut pool.unclaimed_fee_total_sompi, fee_trade)?;
        pool.vault_outpoint = TransactionOutpoint::new(tx.id(), vault_transition.output_index);
        pool.vault_value_sompi = vault_transition.output_value;
        pool.pool_nonce = pool.pool_nonce.checked_add(1).ok_or(NoopReason::SupplyOverflow)?;

        if sender_after == 0 {
            pool.holder_addresses.remove(&seller_owner_id);
        }

        asset.total_supply = supply_after;
        asset.liquidity = Some(pool);
        self.validate_liquidity_invariants(&asset)?;
        self.set_asset_state(op.asset_id, asset);
        if sender_after == 0 {
            self.remove_balance(sender_key);
        } else {
            self.set_balance_amount(sender_key, sender_after);
        }
        Ok(())
    }

    fn execute_claim_liquidity_fees(
        &mut self,
        tx: &Transaction,
        claimant_owner_id: [u8; 32],
        op: &ClaimLiquidityFeesOp,
        auth_inputs: &HashMap<TransactionOutpoint, UtxoEntry>,
        journal: &mut JournalBuilder,
    ) -> Result<(), NoopReason> {
        let mut asset = self.asset_value(&op.asset_id).ok_or(NoopReason::AssetNotFound)?;
        if !matches!(asset.asset_class, TokenAssetClass::Liquidity) {
            return Err(NoopReason::LegacyOpForLiquidityAsset);
        }
        let mut pool = asset.liquidity.clone().ok_or(NoopReason::AssetNotFound)?;
        if pool.pool_nonce != op.expected_pool_nonce {
            return Err(NoopReason::NonceStale);
        }
        if liquidity_sell_locked(&pool) {
            return Err(NoopReason::LiquiditySellLocked);
        }
        if op.claim_amount_sompi < LIQUIDITY_MIN_PAYOUT_SOMPI {
            return Err(NoopReason::InvalidAmount);
        }
        let recipient_index = usize::from(op.recipient_index);
        if recipient_index >= pool.fee_recipients.len() {
            return Err(NoopReason::BadLength);
        }
        let recipient_owner_id = pool.fee_recipients[recipient_index].owner_id;
        let recipient_unclaimed = pool.fee_recipients[recipient_index].unclaimed_sompi;
        if recipient_unclaimed < op.claim_amount_sompi {
            return Err(NoopReason::InsufficientBalance);
        }
        validate_liquidity_claim_authorization(claimant_owner_id, recipient_owner_id)?;

        self.validate_payout_output(tx, op.claim_receive_output_index, op.claim_amount_sompi, Some(recipient_owner_id))?;
        let vault_transition = self.resolve_liquidity_vault_transition(tx, auth_inputs, pool.vault_outpoint)?;
        let vault_delta =
            vault_transition.input_value.checked_sub(vault_transition.output_value).ok_or(NoopReason::SupplyUnderflow)?;
        if vault_delta != op.claim_amount_sompi {
            return Err(NoopReason::VaultOutpointMismatch);
        }

        self.record_asset_before(op.asset_id, journal);

        pool.fee_recipients[recipient_index].unclaimed_sompi = recipient_unclaimed - op.claim_amount_sompi;
        pool.unclaimed_fee_total_sompi =
            pool.unclaimed_fee_total_sompi.checked_sub(op.claim_amount_sompi).ok_or(NoopReason::SupplyUnderflow)?;
        pool.vault_outpoint = TransactionOutpoint::new(tx.id(), vault_transition.output_index);
        pool.vault_value_sompi = vault_transition.output_value;
        pool.pool_nonce = pool.pool_nonce.checked_add(1).ok_or(NoopReason::SupplyOverflow)?;

        asset.liquidity = Some(pool);
        self.validate_liquidity_invariants(&asset)?;
        self.set_asset_state(op.asset_id, asset);
        Ok(())
    }

    fn collect_spent_liquidity_vault_inputs(
        &self,
        tx: &Transaction,
        auth_inputs: &HashMap<TransactionOutpoint, UtxoEntry>,
    ) -> Result<Vec<([u8; 32], TransactionOutpoint)>, NoopReason> {
        let mut spent = Vec::new();
        for input in tx.inputs.iter() {
            let entry = auth_inputs.get(&input.previous_outpoint).ok_or(NoopReason::BadAuthInput)?;
            if !matches!(ScriptClass::from_script(&entry.script_public_key), ScriptClass::LiquidityVault) {
                continue;
            }
            let Some(asset_id) = self.find_liquidity_asset_by_vault_outpoint(input.previous_outpoint)? else {
                return Err(NoopReason::VaultOutpointMismatch);
            };
            spent.push((asset_id, input.previous_outpoint));
        }
        Ok(spent)
    }

    fn find_liquidity_asset_by_vault_outpoint(&self, outpoint: TransactionOutpoint) -> Result<Option<[u8; 32]>, NoopReason> {
        if let Some(asset_id) = self.liquidity_vault_outpoints.get(&outpoint).copied() {
            let asset = self.asset_value(&asset_id).ok_or(NoopReason::InternalMalformedAcceptance)?;
            let pool = asset.liquidity.as_ref().ok_or(NoopReason::InternalMalformedAcceptance)?;
            if !matches!(asset.asset_class, TokenAssetClass::Liquidity) || pool.vault_outpoint != outpoint {
                return Err(NoopReason::InternalMalformedAcceptance);
            }
            return Ok(Some(asset_id));
        }
        if let Some(asset_id) =
            self.state_store.as_ref().and_then(|store| store.get_liquidity_asset_by_vault_outpoint(&outpoint).ok().flatten())
        {
            let asset = self.asset_value(&asset_id).ok_or(NoopReason::InternalMalformedAcceptance)?;
            let pool = asset.liquidity.as_ref().ok_or(NoopReason::InternalMalformedAcceptance)?;
            if !matches!(asset.asset_class, TokenAssetClass::Liquidity) || pool.vault_outpoint != outpoint {
                return Err(NoopReason::InternalMalformedAcceptance);
            }
            return Ok(Some(asset_id));
        }

        let mut matched = None;
        for (asset_id, asset) in self.assets.iter() {
            let Some(pool) = asset.liquidity.as_ref() else {
                continue;
            };
            if !matches!(asset.asset_class, TokenAssetClass::Liquidity) || pool.vault_outpoint != outpoint {
                continue;
            }
            if matched.replace(*asset_id).is_some() {
                return Err(NoopReason::InternalMalformedAcceptance);
            }
        }
        Ok(matched)
    }

    fn resolve_create_liquidity_vault_output(&self, tx: &Transaction) -> Result<(u32, u64), NoopReason> {
        let mut found: Option<(u32, u64)> = None;
        for (index, output) in tx.outputs.iter().enumerate() {
            if !matches!(ScriptClass::from_script(&output.script_public_key), ScriptClass::LiquidityVault) {
                continue;
            }
            let out_index = u32::try_from(index).map_err(|_| NoopReason::BadLength)?;
            if found.is_some() {
                return Err(NoopReason::VaultOutputCount);
            }
            found = Some((out_index, output.value));
        }
        found.ok_or(NoopReason::VaultOutputCount)
    }

    fn resolve_liquidity_vault_transition(
        &self,
        tx: &Transaction,
        auth_inputs: &HashMap<TransactionOutpoint, UtxoEntry>,
        expected_vault_outpoint: TransactionOutpoint,
    ) -> Result<VaultTransition, NoopReason> {
        let mut input_value = None;
        for input in tx.inputs.iter() {
            let Some(entry) = auth_inputs.get(&input.previous_outpoint) else {
                continue;
            };
            if !matches!(ScriptClass::from_script(&entry.script_public_key), ScriptClass::LiquidityVault) {
                continue;
            }
            if input_value.is_some() {
                return Err(NoopReason::VaultInputCount);
            }
            if input.previous_outpoint != expected_vault_outpoint {
                return Err(NoopReason::VaultOutpointMismatch);
            }
            input_value = Some(entry.amount);
        }
        let input_value = input_value.ok_or(NoopReason::VaultInputCount)?;

        let mut output = None;
        for (index, tx_output) in tx.outputs.iter().enumerate() {
            if !matches!(ScriptClass::from_script(&tx_output.script_public_key), ScriptClass::LiquidityVault) {
                continue;
            }
            if output.is_some() {
                return Err(NoopReason::VaultOutputCount);
            }
            let out_index = u32::try_from(index).map_err(|_| NoopReason::BadLength)?;
            output = Some((out_index, tx_output.value));
        }
        let (output_index, output_value) = output.ok_or(NoopReason::VaultOutputCount)?;
        Ok(VaultTransition { input_value, output_index, output_value })
    }

    fn build_fee_recipient_state(
        &self,
        recipients: &[LiquidityRecipientAddress],
    ) -> Result<Vec<LiquidityFeeRecipientState>, NoopReason> {
        let mut out = Vec::with_capacity(recipients.len());
        for recipient in recipients {
            let owner_id = self
                .owner_id_from_address_components(recipient.address_version, recipient.address_payload.as_slice())
                .ok_or(NoopReason::RecipientEncodingInvalid)?;
            out.push(LiquidityFeeRecipientState {
                owner_id,
                address_version: recipient.address_version,
                address_payload: recipient.address_payload.clone(),
                unclaimed_sompi: 0,
            });
        }
        Ok(out)
    }

    fn owner_id_from_address_components(&self, address_version: u8, address_payload: &[u8]) -> Option<[u8; 32]> {
        let auth_scheme = match address_version {
            0 if address_payload.len() == 32 => OWNER_AUTH_SCHEME_PUBKEY,
            1 if address_payload.len() == 33 => OWNER_AUTH_SCHEME_PUBKEY_ECDSA,
            8 if address_payload.len() == 32 => OWNER_AUTH_SCHEME_SCRIPT_HASH,
            _ => return None,
        };
        let pubkey_len = u16::try_from(address_payload.len()).ok()?;
        let mut hasher = Blake2bParams::new().hash_length(32).to_state();
        hasher.update(CAT_OWNER_DOMAIN);
        hasher.update(&[auth_scheme]);
        hasher.update(&pubkey_len.to_le_bytes());
        hasher.update(address_payload);
        let hash = hasher.finalize();
        let mut owner_id = [0u8; 32];
        owner_id.copy_from_slice(hash.as_bytes());
        Some(owner_id)
    }

    fn apply_fee_to_pool(
        &self,
        recipients: &mut [LiquidityFeeRecipientState],
        unclaimed_fee_total_sompi: &mut u64,
        fee_trade: u64,
    ) -> Result<(), NoopReason> {
        if fee_trade == 0 {
            return Ok(());
        }
        *unclaimed_fee_total_sompi = unclaimed_fee_total_sompi.checked_add(fee_trade).ok_or(NoopReason::SupplyOverflow)?;
        match recipients.len() {
            0 => Err(NoopReason::BadLiquidityRecipientCount),
            1 => {
                recipients[0].unclaimed_sompi =
                    recipients[0].unclaimed_sompi.checked_add(fee_trade).ok_or(NoopReason::SupplyOverflow)?;
                Ok(())
            }
            2 => {
                let fee0 = fee_trade / 2;
                let fee1 = fee_trade - fee0;
                recipients[0].unclaimed_sompi = recipients[0].unclaimed_sompi.checked_add(fee0).ok_or(NoopReason::SupplyOverflow)?;
                recipients[1].unclaimed_sompi = recipients[1].unclaimed_sompi.checked_add(fee1).ok_or(NoopReason::SupplyOverflow)?;
                Ok(())
            }
            _ => Err(NoopReason::BadLiquidityRecipientCount),
        }
    }

    fn validate_liquidity_invariants(&self, asset: &TokenAsset) -> Result<(), NoopReason> {
        if !matches!(asset.asset_class, TokenAssetClass::Liquidity) {
            return Ok(());
        }
        let pool = asset.liquidity.as_ref().ok_or(NoopReason::AssetNotFound)?;
        validate_liquidity_curve_mode(pool.curve_mode).map_err(|_| NoopReason::BadLiquidityCurveMode)?;
        validate_liquidity_curve_parameters(
            pool.curve_mode,
            pool.individual_virtual_cpay_reserves_sompi,
            pool.individual_virtual_token_multiplier_bps,
        )
        .map_err(|_| NoopReason::BadLiquidityCurveMode)?;
        validate_liquidity_unlock_target(pool.unlock_target_sompi)?;
        if pool.unlock_target_sompi == 0 && !pool.unlocked {
            return Err(NoopReason::InternalMalformedAcceptance);
        }
        if pool.unlock_target_sompi > 0 && !pool.unlocked && pool.real_cpay_reserves_sompi >= pool.unlock_target_sompi {
            return Err(NoopReason::InternalMalformedAcceptance);
        }
        validate_real_cpay_reserve(pool.real_cpay_reserves_sompi)?;
        if pool.real_token_reserves < MIN_REAL_TOKEN_RESERVE {
            return Err(NoopReason::InternalMalformedAcceptance);
        }
        let expected_vault =
            pool.real_cpay_reserves_sompi.checked_add(pool.unclaimed_fee_total_sompi).ok_or(NoopReason::SupplyOverflow)?;
        if pool.vault_value_sompi != expected_vault {
            return Err(NoopReason::InternalMalformedAcceptance);
        }
        let expected_total = asset.total_supply.checked_add(pool.real_token_reserves).ok_or(NoopReason::SupplyOverflow)?;
        if expected_total != asset.max_supply {
            return Err(NoopReason::InternalMalformedAcceptance);
        }
        if pool.virtual_cpay_reserves_sompi == 0 || pool.virtual_token_reserves == 0 {
            return Err(NoopReason::InternalMalformedAcceptance);
        }
        for (holder_owner_id, holder_address) in pool.holder_addresses.iter() {
            let derived_owner_id = self
                .owner_id_from_address_components(holder_address.address_version, holder_address.address_payload.as_slice())
                .ok_or(NoopReason::InternalMalformedAcceptance)?;
            if &derived_owner_id != holder_owner_id {
                return Err(NoopReason::InternalMalformedAcceptance);
            }
        }
        Ok(())
    }

    fn validate_payout_output(
        &self,
        tx: &Transaction,
        output_index: u16,
        expected_value: u64,
        expected_owner_id: Option<[u8; 32]>,
    ) -> Result<(), NoopReason> {
        let output = tx.outputs.get(output_index as usize).ok_or(NoopReason::BadLength)?;
        if output.value != expected_value {
            return Err(NoopReason::InvalidAmount);
        }
        let class = ScriptClass::from_script(&output.script_public_key);
        if !matches!(class, ScriptClass::PubKey | ScriptClass::PubKeyECDSA | ScriptClass::ScriptHash) {
            return Err(NoopReason::PayoutScriptClassInvalid);
        }
        if let Some(owner_id) = expected_owner_id {
            let payout_owner_id =
                self.owner_id_from_script_if_whitelisted(&output.script_public_key).ok_or(NoopReason::BadAuthInput)?;
            if payout_owner_id != owner_id {
                return Err(NoopReason::BadAuthInput);
            }
        }
        Ok(())
    }

    fn build_event_details(
        &self,
        tx: &Transaction,
        parsed: &ParsedTokenPayload,
        auth_inputs: &HashMap<TransactionOutpoint, UtxoEntry>,
    ) -> TokenEventDetails {
        let from_owner_id = self.resolve_event_from_owner_id(tx, parsed.header.auth_input_index, auth_inputs);
        match &parsed.op {
            TokenOp::CreateAsset(_) => TokenEventDetails {
                op_type: Some(TokenOpCode::CreateAsset),
                asset_id: Some(tx.id().as_bytes()),
                from_owner_id,
                to_owner_id: None,
                amount: None,
            },
            TokenOp::Transfer(op) => TokenEventDetails {
                op_type: Some(TokenOpCode::Transfer),
                asset_id: Some(op.asset_id),
                from_owner_id,
                to_owner_id: Some(op.to_owner_id),
                amount: Some(op.amount),
            },
            TokenOp::Mint(op) => TokenEventDetails {
                op_type: Some(TokenOpCode::Mint),
                asset_id: Some(op.asset_id),
                from_owner_id,
                to_owner_id: Some(op.to_owner_id),
                amount: Some(op.amount),
            },
            TokenOp::Burn(op) => TokenEventDetails {
                op_type: Some(TokenOpCode::Burn),
                asset_id: Some(op.asset_id),
                from_owner_id,
                to_owner_id: None,
                amount: Some(op.amount),
            },
            TokenOp::CreateAssetWithMint(op) => TokenEventDetails {
                op_type: Some(TokenOpCode::CreateAssetWithMint),
                asset_id: Some(tx.id().as_bytes()),
                from_owner_id,
                to_owner_id: if op.initial_mint_amount > 0 { Some(op.initial_mint_to_owner_id) } else { None },
                amount: if op.initial_mint_amount > 0 { Some(op.initial_mint_amount) } else { None },
            },
            TokenOp::CreateLiquidityAsset(op) => TokenEventDetails {
                op_type: Some(TokenOpCode::CreateLiquidityAsset),
                asset_id: Some(tx.id().as_bytes()),
                from_owner_id,
                to_owner_id: None,
                amount: Some(op.launch_buy_min_token_out),
            },
            TokenOp::BuyLiquidityExactIn(op) => TokenEventDetails {
                op_type: Some(TokenOpCode::BuyLiquidityExactIn),
                asset_id: Some(op.asset_id),
                from_owner_id,
                to_owner_id: from_owner_id,
                amount: Some(op.min_token_out),
            },
            TokenOp::SellLiquidityExactIn(op) => TokenEventDetails {
                op_type: Some(TokenOpCode::SellLiquidityExactIn),
                asset_id: Some(op.asset_id),
                from_owner_id,
                to_owner_id: None,
                amount: Some(op.token_in),
            },
            TokenOp::ClaimLiquidityFees(op) => TokenEventDetails {
                op_type: Some(TokenOpCode::ClaimLiquidityFees),
                asset_id: Some(op.asset_id),
                from_owner_id,
                to_owner_id: None,
                amount: Some(u128::from(op.claim_amount_sompi)),
            },
        }
    }

    fn resolve_event_from_owner_id(
        &self,
        tx: &Transaction,
        auth_input_index: u16,
        auth_inputs: &HashMap<TransactionOutpoint, UtxoEntry>,
    ) -> Option<[u8; 32]> {
        let auth_idx = auth_input_index as usize;
        if auth_idx >= tx.inputs.len() {
            return None;
        }
        let outpoint = tx.inputs[auth_idx].previous_outpoint;
        let entry = auth_inputs.get(&outpoint)?;
        self.owner_id_from_script_if_whitelisted(&entry.script_public_key)
    }

    fn resolve_auth_context(
        &self,
        tx: &Transaction,
        auth_input_index: u16,
        auth_inputs: &HashMap<TransactionOutpoint, UtxoEntry>,
    ) -> Result<AuthContext, NoopReason> {
        let auth_idx = auth_input_index as usize;
        if auth_idx >= tx.inputs.len() {
            return Err(NoopReason::BadAuthInput);
        }

        let outpoint = tx.inputs[auth_idx].previous_outpoint;
        let entry = auth_inputs.get(&outpoint).ok_or(NoopReason::BadAuthInput)?;
        let owner_id = self.owner_id_from_script(&entry.script_public_key)?;
        let (auth_scheme, canonical_pubkey_bytes) =
            self.canonical_owner_identity(&entry.script_public_key).ok_or(NoopReason::BadAuthInput)?;
        let address_version = self.address_version_from_auth_scheme(auth_scheme).ok_or(NoopReason::BadAuthInput)?;
        Ok(AuthContext { owner_id, address_version, address_payload: canonical_pubkey_bytes.to_vec() })
    }

    fn owner_id_from_script(&self, script_public_key: &ScriptPublicKey) -> Result<[u8; 32], NoopReason> {
        self.owner_id_from_script_if_whitelisted(script_public_key).ok_or(NoopReason::BadAuthInput)
    }

    fn owner_id_from_script_if_whitelisted(&self, script_public_key: &ScriptPublicKey) -> Option<[u8; 32]> {
        let (auth_scheme, canonical_pubkey_bytes) = self.canonical_owner_identity(script_public_key)?;
        let pubkey_len = u16::try_from(canonical_pubkey_bytes.len()).ok()?;
        let mut hasher = Blake2bParams::new().hash_length(32).to_state();
        hasher.update(CAT_OWNER_DOMAIN);
        hasher.update(&[auth_scheme]);
        hasher.update(&pubkey_len.to_le_bytes());
        hasher.update(canonical_pubkey_bytes);
        let hash = hasher.finalize();
        let mut owner_id = [0u8; 32];
        owner_id.copy_from_slice(hash.as_bytes());
        Some(owner_id)
    }

    fn canonical_owner_identity<'a>(&self, script_public_key: &'a ScriptPublicKey) -> Option<(u8, &'a [u8])> {
        let script_bytes = script_public_key.script();
        match ScriptClass::from_script(script_public_key) {
            ScriptClass::PubKey if script_bytes.len() == 34 => Some((OWNER_AUTH_SCHEME_PUBKEY, &script_bytes[1..33])),
            ScriptClass::PubKeyECDSA if script_bytes.len() == 35 => Some((OWNER_AUTH_SCHEME_PUBKEY_ECDSA, &script_bytes[1..34])),
            ScriptClass::ScriptHash if script_bytes.len() == 35 => Some((OWNER_AUTH_SCHEME_SCRIPT_HASH, &script_bytes[2..34])),
            _ => None,
        }
    }

    fn address_version_from_auth_scheme(&self, auth_scheme: u8) -> Option<u8> {
        match auth_scheme {
            OWNER_AUTH_SCHEME_PUBKEY => Some(0),
            OWNER_AUTH_SCHEME_PUBKEY_ECDSA => Some(1),
            OWNER_AUTH_SCHEME_SCRIPT_HASH => Some(8),
            _ => None,
        }
    }

    fn insert_processed(
        &mut self,
        txid: BlockHash,
        accepting_block_hash: BlockHash,
        apply_status: ApplyStatus,
        noop_reason: NoopReason,
        _source_block_hash: BlockHash,
        ordinal: u32,
        details: TokenEventDetails,
        journal: &mut JournalBuilder,
    ) {
        let event_type = if matches!(apply_status, ApplyStatus::Applied) { EventType::Applied } else { EventType::Noop };
        let base_event_id = self.compute_event_id(accepting_block_hash, txid, event_type, apply_status, noop_reason, ordinal);

        let event_id = self.push_event(TokenEvent {
            event_id: base_event_id,
            sequence: 0,
            accepting_block_hash,
            txid,
            event_type,
            apply_status,
            noop_reason,
            ordinal,
            reorg_of_event_id: None,
            details: details.clone(),
        });

        journal.tx_results.push(TokenApplyResult { txid, apply_status, noop_reason, ordinal, event_id, details });
        journal.added_processed_ops.push(txid);
        self.set_processed_op_value(txid, ProcessedOp { accepting_block_hash, apply_status, noop_reason });
    }

    fn insert_internal_malformed_noop(
        &mut self,
        accepting_block_hash: BlockHash,
        accepting_block_daa_score: u64,
        tx_ref: &CanonicalTxRef,
        ordinal: u32,
        journal: &mut JournalBuilder,
    ) {
        let tx = &tx_ref.tx;
        if accepting_block_daa_score < self.payload_hf_activation_daa_score {
            return;
        }
        if self.processed_op_value(&tx.id()).is_some() {
            return;
        }
        if !tx.subnetwork_id.is_payload() || tx.payload.is_empty() {
            return;
        }
        if parse_atomic_token_payload(&tx.payload).is_none() {
            return;
        }
        self.insert_processed(
            tx.id(),
            accepting_block_hash,
            ApplyStatus::Noop,
            NoopReason::InternalMalformedAcceptance,
            tx_ref.source_block_hash,
            ordinal,
            TokenEventDetails::default(),
            journal,
        );
    }

    fn record_asset_before(&mut self, asset_id: [u8; 32], journal: &mut JournalBuilder) {
        if journal.seen_assets.insert(asset_id) {
            journal.changed_assets.push(ChangedAsset { asset_id, old_value: self.asset_value(&asset_id) });
        }
    }

    fn record_balance_before(&mut self, key: BalanceKey, journal: &mut JournalBuilder) {
        if journal.seen_balances.insert(key) {
            let old_value = self.balance_value(&key);
            journal.changed_balances.push(ChangedBalance { key, old_value: (old_value > 0).then_some(old_value) });
        }
    }

    fn record_nonce_before(&mut self, key: NonceKey, journal: &mut JournalBuilder) {
        if journal.seen_nonces.insert(key) {
            let old_value = self.nonce_value(&key);
            journal.changed_nonces.push(ChangedNonce { key, old_value: (old_value != 1).then_some(old_value) });
        }
    }

    fn record_anchor_count_before(&mut self, owner_id: [u8; 32], journal: &mut JournalBuilder) {
        if journal.seen_anchor_counts.insert(owner_id) {
            let old_value = self.anchor_count_value(&owner_id);
            journal.changed_anchor_counts.push(ChangedAnchorCount { owner_id, old_value: (old_value > 0).then_some(old_value) });
        }
    }

    fn reserve_event_id(&mut self, requested_event_id: [u8; 32]) -> [u8; 32] {
        if self.event_ids.insert(requested_event_id) {
            return requested_event_id;
        }

        let mut nonce = self.next_event_sequence.saturating_add(1);
        loop {
            let mut hasher = Blake2bParams::new().hash_length(32).to_state();
            hasher.update(CAT_EVENT_INSTANCE_DOMAIN);
            hasher.update(&requested_event_id);
            hasher.update(&nonce.to_le_bytes());
            let digest = hasher.finalize();
            let mut candidate = [0u8; 32];
            candidate.copy_from_slice(digest.as_bytes());

            if self.event_ids.insert(candidate) {
                return candidate;
            }
            nonce = nonce.saturating_add(1);
        }
    }

    fn push_event(&mut self, mut event: TokenEvent) -> [u8; 32] {
        event.event_id = self.reserve_event_id(event.event_id);
        self.next_event_sequence = self.next_event_sequence.saturating_add(1);
        event.sequence = self.next_event_sequence;
        let event_id = event.event_id;
        self.events.push(event);
        event_id
    }

    pub(crate) fn rebuild_event_id_index(&mut self) {
        self.event_ids = self.events.iter().map(|event| event.event_id).collect();
    }

    fn compute_event_id(
        &self,
        accepting_block_hash: BlockHash,
        txid: BlockHash,
        event_type: EventType,
        apply_status: ApplyStatus,
        noop_reason: NoopReason,
        ordinal: u32,
    ) -> [u8; 32] {
        let network_id_bytes = self.network_id.as_bytes();
        let network_len = u16::try_from(network_id_bytes.len()).unwrap_or(0);

        let mut hasher = Blake2bParams::new().hash_length(32).to_state();
        hasher.update(CAT_EVENT_DOMAIN);
        hasher.update(&self.protocol_version.to_le_bytes());
        hasher.update(&network_len.to_le_bytes());
        hasher.update(network_id_bytes);
        hasher.update(&accepting_block_hash.as_bytes());
        hasher.update(&txid.as_bytes());
        hasher.update(&[event_type as u8]);
        hasher.update(&[apply_status as u8]);
        hasher.update(&(noop_reason as u16).to_le_bytes());
        hasher.update(&ordinal.to_le_bytes());
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_bytes());
        out
    }

    pub fn get_balance(&self, asset_id: [u8; 32], owner_id: [u8; 32]) -> u128 {
        self.balance_value(&BalanceKey { asset_id, owner_id })
    }

    pub fn get_owner_nonce(&self, owner_id: [u8; 32]) -> u64 {
        self.nonce_value(&NonceKey::owner(owner_id))
    }

    pub fn get_token_nonce(&self, owner_id: [u8; 32], asset_id: [u8; 32]) -> u64 {
        self.nonce_value(&NonceKey::asset(owner_id, asset_id))
    }

    pub fn get_nonce(&self, owner_id: [u8; 32]) -> u64 {
        self.get_owner_nonce(owner_id)
    }

    pub fn get_asset(&self, asset_id: [u8; 32]) -> Option<TokenAsset> {
        self.asset_value(&asset_id)
    }

    pub fn get_anchor_count(&self, owner_id: [u8; 32]) -> u64 {
        self.anchor_count_value(&owner_id)
    }

    pub fn get_op_status(&self, txid: BlockHash) -> Option<ProcessedOp> {
        self.processed_op_value(&txid)
    }

    pub fn get_state_hash(&self) -> [u8; 32] {
        self.compute_state_hash()
    }

    pub fn get_events_since(&self, after_sequence: u64, limit: usize) -> Vec<TokenEvent> {
        self.events.iter().filter(|event| event.sequence > after_sequence).take(limit).cloned().collect()
    }

    pub fn get_events_since_capped(&self, after_sequence: u64, limit: usize, max_sequence: u64) -> Vec<TokenEvent> {
        self.events
            .iter()
            .filter(|event| event.sequence > after_sequence && event.sequence <= max_sequence)
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn materialize_latest_view(&self, fallback_block_hash: BlockHash) -> AtomicTokenReadView {
        if let Some(last_applied_block_hash) = self.applied_chain_order.last().copied() {
            return AtomicTokenReadView {
                at_block_hash: last_applied_block_hash,
                state_hash: self.compute_state_hash(),
                is_degraded: self.degraded,
                runtime_state: self.runtime_state(false),
                event_sequence_cutoff: self.next_event_sequence,
                assets: self.assets.clone(),
                balances: self.balances.clone(),
                nonces: self.nonces.clone(),
                anchor_counts: self.anchor_counts.clone(),
                processed_ops: self.processed_ops.clone(),
                known_owner_addresses: self.known_owner_addresses.clone(),
            };
        }
        AtomicTokenReadView {
            at_block_hash: fallback_block_hash,
            state_hash: self.compute_state_hash(),
            is_degraded: self.degraded,
            runtime_state: self.runtime_state(false),
            event_sequence_cutoff: self.next_event_sequence,
            assets: self.assets.clone(),
            balances: self.balances.clone(),
            nonces: self.nonces.clone(),
            anchor_counts: self.anchor_counts.clone(),
            processed_ops: self.processed_ops.clone(),
            known_owner_addresses: self.known_owner_addresses.clone(),
        }
    }

    pub fn materialize_latest_context(
        &self,
        fallback_block_hash: BlockHash,
        runtime_state: AtomicTokenRuntimeState,
    ) -> AtomicTokenReadContext {
        AtomicTokenReadContext {
            at_block_hash: self.applied_chain_order.last().copied().unwrap_or(fallback_block_hash),
            state_hash: self.compute_state_hash(),
            is_degraded: self.degraded,
            runtime_state,
            event_sequence_cutoff: self.next_event_sequence,
        }
    }

    pub fn materialize_context_at_block(
        &self,
        at_block_hash: BlockHash,
        runtime_state: AtomicTokenRuntimeState,
    ) -> Option<AtomicTokenReadContext> {
        self.retained_index(at_block_hash)?;
        let state_hash = self.state_hash_by_block.get(&at_block_hash).copied()?;
        let event_sequence_cutoff = self.event_sequence_by_block.get(&at_block_hash).copied().unwrap_or(self.next_event_sequence);
        Some(AtomicTokenReadContext { at_block_hash, state_hash, is_degraded: self.degraded, runtime_state, event_sequence_cutoff })
    }

    fn retained_index(&self, at_block_hash: BlockHash) -> Option<usize> {
        self.applied_chain_order.iter().position(|hash| *hash == at_block_hash)
    }

    pub fn get_asset_at_block(&self, asset_id: [u8; 32], at_block_hash: BlockHash) -> Option<Option<TokenAsset>> {
        let target_index = self.retained_index(at_block_hash)?;
        let mut value = self.asset_value(&asset_id);
        for block_hash in self.applied_chain_order.iter().skip(target_index + 1).rev().copied() {
            let journal = self.block_journals.get(&block_hash)?;
            for change in journal.changed_assets.iter().rev() {
                if change.asset_id == asset_id {
                    value = change.old_value.clone();
                    break;
                }
            }
        }
        Some(value)
    }

    pub fn get_balance_at_block(&self, key: BalanceKey, at_block_hash: BlockHash) -> Option<u128> {
        let target_index = self.retained_index(at_block_hash)?;
        let mut value = self.balance_value(&key);
        for block_hash in self.applied_chain_order.iter().skip(target_index + 1).rev().copied() {
            let journal = self.block_journals.get(&block_hash)?;
            for change in journal.changed_balances.iter().rev() {
                if change.key == key {
                    value = change.old_value.unwrap_or(0);
                    break;
                }
            }
        }
        Some(value)
    }

    pub fn get_nonce_at_block(&self, key: NonceKey, at_block_hash: BlockHash) -> Option<u64> {
        let target_index = self.retained_index(at_block_hash)?;
        let mut value = self.nonce_value(&key);
        for block_hash in self.applied_chain_order.iter().skip(target_index + 1).rev().copied() {
            let journal = self.block_journals.get(&block_hash)?;
            for change in journal.changed_nonces.iter().rev() {
                if change.key == key {
                    value = change.old_value.unwrap_or(1);
                    break;
                }
            }
        }
        Some(value)
    }

    pub fn get_anchor_count_at_block(&self, owner_id: [u8; 32], at_block_hash: BlockHash) -> Option<u64> {
        let target_index = self.retained_index(at_block_hash)?;
        let mut value = self.anchor_count_value(&owner_id);
        for block_hash in self.applied_chain_order.iter().skip(target_index + 1).rev().copied() {
            let journal = self.block_journals.get(&block_hash)?;
            for change in journal.changed_anchor_counts.iter().rev() {
                if change.owner_id == owner_id {
                    value = change.old_value.unwrap_or(0);
                    break;
                }
            }
        }
        Some(value)
    }

    pub fn get_processed_op_at_block(&self, txid: BlockHash, at_block_hash: BlockHash) -> Option<Option<ProcessedOp>> {
        let target_index = self.retained_index(at_block_hash)?;
        let mut value = self.processed_op_value(&txid);
        for block_hash in self.applied_chain_order.iter().skip(target_index + 1).rev().copied() {
            let journal = self.block_journals.get(&block_hash)?;
            if journal.added_processed_ops.iter().any(|added| *added == txid) {
                value = None;
            }
        }
        Some(value)
    }

    pub fn indexed_assets_page(&self, offset: usize, limit: usize, query: &str) -> (Vec<TokenAsset>, u64) {
        if self.assets.is_empty() && self.deleted_assets.is_empty() {
            if let Some((assets, total)) = self.state_store.as_ref().and_then(|store| store.assets_page(offset, limit, query).ok()) {
                return (assets, total);
            }
        }

        let mut assets = self
            .state_store
            .as_ref()
            .and_then(|store| store.assets_page(0, usize::MAX, query).ok())
            .map(|(assets, _)| assets)
            .unwrap_or_default();
        assets.retain(|asset| !self.deleted_assets.contains(&asset.asset_id));
        for asset in self.assets.values() {
            if asset_matches_query(asset, query) {
                if let Some(existing) = assets.iter_mut().find(|existing| existing.asset_id == asset.asset_id) {
                    *existing = asset.clone();
                } else {
                    assets.push(asset.clone());
                }
            }
        }
        assets.sort_by(|a, b| a.asset_id.cmp(&b.asset_id));
        let total = assets.len() as u64;
        let page = assets.into_iter().skip(offset).take(limit).collect();
        (page, total)
    }

    pub fn indexed_assets_page_at_block(
        &self,
        offset: usize,
        limit: usize,
        query: &str,
        at_block_hash: BlockHash,
    ) -> Option<(Vec<TokenAsset>, u64)> {
        let target_index = self.retained_index(at_block_hash)?;

        let mut changed_assets: HashMap<[u8; 32], Option<TokenAsset>> = HashMap::new();
        for block_hash in self.applied_chain_order.iter().skip(target_index + 1).rev().copied() {
            let journal = self.block_journals.get(&block_hash)?;
            for change in journal.changed_assets.iter().rev() {
                changed_assets.entry(change.asset_id).or_insert_with(|| change.old_value.clone());
            }
        }

        if self.assets.is_empty() && self.deleted_assets.is_empty() {
            if let Some(store) = self.state_store.as_ref() {
                let excluded = changed_assets.keys().copied().collect::<HashSet<_>>();
                let mut override_assets =
                    changed_assets.into_values().flatten().filter(|asset| asset_matches_query(asset, query)).collect::<Vec<_>>();
                override_assets.sort_by(|a, b| a.asset_id.cmp(&b.asset_id));

                let mut total = 0u64;
                let mut page = Vec::with_capacity(limit.min(1024));
                let mut override_index = 0usize;
                let mut emit_asset = |asset: TokenAsset| {
                    if total >= offset as u64 && page.len() < limit {
                        page.push(asset);
                    }
                    total = total.saturating_add(1);
                };

                store
                    .visit_assets_excluding(query, &excluded, |base_asset| {
                        while override_index < override_assets.len() && override_assets[override_index].asset_id < base_asset.asset_id
                        {
                            emit_asset(override_assets[override_index].clone());
                            override_index += 1;
                        }
                        emit_asset(base_asset);
                        Ok(())
                    })
                    .ok()?;
                while override_index < override_assets.len() {
                    emit_asset(override_assets[override_index].clone());
                    override_index += 1;
                }
                return Some((page, total));
            }
        }

        let mut view = self.materialize_view_at_block(at_block_hash)?;
        let mut assets =
            view.assets.drain().map(|(_, asset)| asset).filter(|asset| asset_matches_query(asset, query)).collect::<Vec<_>>();
        assets.sort_by(|a, b| a.asset_id.cmp(&b.asset_id));
        let total = assets.len() as u64;
        let page = assets.into_iter().skip(offset).take(limit).collect();
        Some((page, total))
    }

    pub fn indexed_balances_by_owner(&self, owner_id: [u8; 32], include_assets: bool) -> Vec<TokenOwnerBalanceEntry> {
        let mut by_asset: HashMap<[u8; 32], u128> = self
            .state_store
            .as_ref()
            .and_then(|store| store.balances_by_owner(&owner_id).ok())
            .unwrap_or_default()
            .into_iter()
            .collect();
        if let Some(asset_ids) = self.balances_by_owner.get(&owner_id) {
            for asset_id in asset_ids.iter().copied() {
                let key = BalanceKey { asset_id, owner_id };
                by_asset.insert(asset_id, self.balance_value(&key));
            }
        }
        for key in self.deleted_balances.iter().filter(|key| key.owner_id == owner_id) {
            by_asset.remove(&key.asset_id);
        }

        let mut entries = Vec::with_capacity(by_asset.len());
        for (asset_id, balance) in by_asset {
            if balance == 0 {
                continue;
            }
            let asset = if include_assets { self.asset_value(&asset_id) } else { None };
            entries.push((asset_id, balance, asset));
        }
        entries
    }

    pub fn indexed_balances_by_owner_at_block(
        &self,
        owner_id: [u8; 32],
        include_assets: bool,
        at_block_hash: BlockHash,
    ) -> Option<Vec<TokenOwnerBalanceEntry>> {
        let target_index = self.retained_index(at_block_hash)?;
        let mut by_asset: HashMap<[u8; 32], u128> =
            self.indexed_balances_by_owner(owner_id, false).into_iter().map(|(asset_id, balance, _)| (asset_id, balance)).collect();

        for block_hash in self.applied_chain_order.iter().skip(target_index + 1).rev().copied() {
            let journal = self.block_journals.get(&block_hash)?;
            for change in journal.changed_balances.iter().rev() {
                if change.key.owner_id != owner_id {
                    continue;
                }
                match change.old_value {
                    Some(value) if value > 0 => {
                        by_asset.insert(change.key.asset_id, value);
                    }
                    _ => {
                        by_asset.remove(&change.key.asset_id);
                    }
                }
            }
        }

        let mut entries = Vec::with_capacity(by_asset.len());
        for (asset_id, balance) in by_asset {
            if balance == 0 {
                continue;
            }
            let asset = if include_assets { self.get_asset_at_block(asset_id, at_block_hash)? } else { None };
            entries.push((asset_id, balance, asset));
        }
        Some(entries)
    }

    pub fn indexed_holders_by_asset(&self, asset_id: [u8; 32]) -> Vec<TokenHolderEntry> {
        let mut by_owner: HashMap<[u8; 32], u128> = self
            .state_store
            .as_ref()
            .and_then(|store| store.holders_by_asset(&asset_id).ok())
            .unwrap_or_default()
            .into_iter()
            .collect();
        if let Some(owner_ids) = self.holders_by_asset.get(&asset_id) {
            for owner_id in owner_ids.iter().copied() {
                let key = BalanceKey { asset_id, owner_id };
                by_owner.insert(owner_id, self.balance_value(&key));
            }
        }
        for key in self.deleted_balances.iter().filter(|key| key.asset_id == asset_id) {
            by_owner.remove(&key.owner_id);
        }

        let mut entries = Vec::with_capacity(by_owner.len());
        for (owner_id, balance) in by_owner {
            if balance > 0 {
                entries.push((owner_id, balance));
            }
        }
        entries
    }

    pub fn indexed_holders_by_asset_at_block(&self, asset_id: [u8; 32], at_block_hash: BlockHash) -> Option<Vec<TokenHolderEntry>> {
        let target_index = self.retained_index(at_block_hash)?;
        let mut by_owner: HashMap<[u8; 32], u128> =
            self.indexed_holders_by_asset(asset_id).into_iter().map(|(owner_id, balance)| (owner_id, balance)).collect();

        for block_hash in self.applied_chain_order.iter().skip(target_index + 1).rev().copied() {
            let journal = self.block_journals.get(&block_hash)?;
            for change in journal.changed_balances.iter().rev() {
                if change.key.asset_id != asset_id {
                    continue;
                }
                match change.old_value {
                    Some(value) if value > 0 => {
                        by_owner.insert(change.key.owner_id, value);
                    }
                    _ => {
                        by_owner.remove(&change.key.owner_id);
                    }
                }
            }
        }

        Some(by_owner.into_iter().filter(|(_, balance)| *balance > 0).collect())
    }

    pub fn indexed_liquidity_holder_addresses(
        &self,
        asset_id: [u8; 32],
        holders: &[TokenHolderEntry],
    ) -> HashMap<[u8; 32], LiquidityHolderAddressState> {
        let asset = self.asset_value(&asset_id);
        let pool_holder_addresses = asset.as_ref().and_then(|asset| asset.liquidity.as_ref()).map(|pool| &pool.holder_addresses);

        holders
            .iter()
            .filter_map(|(owner_id, _)| {
                if let Some(holder) = pool_holder_addresses
                    .and_then(|addresses| addresses.get(owner_id))
                    .or_else(|| self.known_owner_addresses.get(owner_id))
                {
                    return Some((*owner_id, holder.clone()));
                }
                self.state_store
                    .as_ref()
                    .and_then(|store| store.get_known_owner_address(owner_id).ok().flatten())
                    .map(|holder| (*owner_id, holder))
            })
            .collect()
    }

    pub fn materialize_view_at_block(&self, at_block_hash: BlockHash) -> Option<AtomicTokenReadView> {
        let target_index = self.applied_chain_order.iter().position(|hash| *hash == at_block_hash)?;
        let mut assets = self.assets.clone();
        let mut balances = self.balances.clone();
        let mut nonces = self.nonces.clone();
        let mut anchor_counts = self.anchor_counts.clone();
        let mut processed_ops = self.processed_ops.clone();

        for block_hash in self.applied_chain_order.iter().skip(target_index + 1).rev().copied() {
            let journal = self.block_journals.get(&block_hash)?;

            for change in journal.changed_assets.iter().rev() {
                match &change.old_value {
                    Some(asset) => {
                        assets.insert(change.asset_id, asset.clone());
                    }
                    None => {
                        assets.remove(&change.asset_id);
                    }
                }
            }

            for change in journal.changed_balances.iter().rev() {
                match change.old_value {
                    Some(value) => {
                        balances.insert(change.key, value);
                    }
                    None => {
                        balances.remove(&change.key);
                    }
                }
            }

            for change in journal.changed_nonces.iter().rev() {
                match change.old_value {
                    Some(value) => {
                        nonces.insert(change.key, value);
                    }
                    None => {
                        nonces.remove(&change.key);
                    }
                }
            }

            for change in journal.changed_anchor_counts.iter().rev() {
                match change.old_value {
                    Some(value) => {
                        anchor_counts.insert(change.owner_id, value);
                    }
                    None => {
                        anchor_counts.remove(&change.owner_id);
                    }
                }
            }

            for txid in journal.added_processed_ops.iter().copied() {
                processed_ops.remove(&txid);
            }
        }

        let event_sequence_cutoff = self.event_sequence_by_block.get(&at_block_hash).copied().unwrap_or(self.next_event_sequence);
        let known_owner_addresses = Self::known_owner_addresses_from_assets(&assets);
        let mut view = AtomicTokenReadView {
            at_block_hash,
            state_hash: [0u8; 32],
            is_degraded: self.degraded,
            runtime_state: self.runtime_state(false),
            event_sequence_cutoff,
            assets,
            balances,
            nonces,
            anchor_counts,
            processed_ops,
            known_owner_addresses,
        };
        view.state_hash = self.compute_state_hash_for_view(view.clone());
        Some(view)
    }

    pub fn get_health(&self) -> AtomicTokenHealth {
        AtomicTokenHealth {
            is_degraded: self.degraded,
            bootstrap_in_progress: false,
            live_correct: self.live_correct,
            runtime_state: self.runtime_state(false),
            last_applied_block: self.applied_chain_order.last().copied(),
            last_sequence: self.next_event_sequence,
            current_state_hash: self.compute_state_hash(),
        }
    }

    pub fn get_state_hash_at_block(&self, at_block_hash: BlockHash) -> Option<[u8; 32]> {
        self.state_hash_by_block.get(&at_block_hash).copied()
    }

    #[cfg(test)]
    pub fn export_snapshot(
        &self,
        at_block_hash: BlockHash,
        at_daa_score: u64,
        window_start_parent_block_hash: BlockHash,
        window_blocks: &[BlockHash],
    ) -> AtomicTokenResult<AtomicTokenSnapshot> {
        if window_blocks.is_empty() {
            return Err(AtomicTokenError::Processing("cannot export snapshot with empty rollback window".to_string()));
        }

        let target_index = self.applied_chain_order.iter().position(|hash| *hash == at_block_hash).ok_or_else(|| {
            AtomicTokenError::Processing(format!("snapshot export failed: at_block_hash `{at_block_hash}` not found in applied chain"))
        })?;
        let window_start_block_hash = window_blocks[0];
        let window_end_block_hash = *window_blocks.last().unwrap();
        if window_end_block_hash != at_block_hash {
            return Err(AtomicTokenError::Processing("snapshot export window end must match snapshot at_block_hash".to_string()));
        }
        let window_start_index =
            self.applied_chain_order.iter().position(|hash| *hash == window_start_block_hash).ok_or_else(|| {
                AtomicTokenError::Processing(format!(
                    "snapshot export failed: window_start_block_hash `{window_start_block_hash}` not found in applied chain"
                ))
            })?;
        if window_start_index > target_index {
            return Err(AtomicTokenError::Processing(
                "snapshot export failed: window_start_block_hash appears after at_block_hash".to_string(),
            ));
        }
        let expected_window = &self.applied_chain_order[window_start_index..=target_index];
        if expected_window != window_blocks {
            return Err(AtomicTokenError::Processing(
                "snapshot export failed: rollback window is not a contiguous canonical chain segment".to_string(),
            ));
        }
        if window_start_index > 0 && self.applied_chain_order[window_start_index - 1] != window_start_parent_block_hash {
            return Err(AtomicTokenError::Processing(
                "snapshot export failed: window_start_parent_block_hash does not match canonical chain parent".to_string(),
            ));
        }

        let mut journals_in_window = Vec::with_capacity(window_blocks.len());
        for block_hash in window_blocks.iter().copied() {
            let journal = self.block_journals.get(&block_hash).cloned().ok_or_else(|| {
                AtomicTokenError::Processing(format!("missing block journal in snapshot window for block `{block_hash}`"))
            })?;
            journals_in_window.push((block_hash, journal));
        }

        let view = self.materialize_view_at_block(at_block_hash).ok_or_else(|| {
            AtomicTokenError::Processing(format!("snapshot export failed: unable to materialize state at block `{at_block_hash}`"))
        })?;
        let applied_chain_order = self.applied_chain_order[window_start_index..=target_index].to_vec();
        let mut state_hash_by_block = HashMap::with_capacity(applied_chain_order.len());
        for block_hash in applied_chain_order.iter().copied() {
            let state_hash = self.state_hash_by_block.get(&block_hash).copied().ok_or_else(|| {
                AtomicTokenError::Processing(format!("snapshot export failed: missing state hash checkpoint for block `{block_hash}`"))
            })?;
            state_hash_by_block.insert(block_hash, state_hash);
        }
        if state_hash_by_block.get(&at_block_hash).copied() != Some(view.state_hash) {
            return Err(AtomicTokenError::Processing(
                "snapshot export failed: retained state hash checkpoint does not match materialized anchor state".to_string(),
            ));
        }
        let event_sequence_by_block: HashMap<BlockHash, u64> = applied_chain_order
            .iter()
            .filter_map(|hash| self.event_sequence_by_block.get(hash).copied().map(|seq| (*hash, seq)))
            .collect();
        if state_hash_by_block.len() != applied_chain_order.len() {
            return Err(AtomicTokenError::Processing(
                "snapshot export failed: missing state_hash_by_block entries within chain prefix".to_string(),
            ));
        }
        if event_sequence_by_block.len() != applied_chain_order.len() {
            return Err(AtomicTokenError::Processing(
                "snapshot export failed: missing event_sequence_by_block entries within chain prefix".to_string(),
            ));
        }
        let events = self.events.iter().filter(|event| event.sequence <= view.event_sequence_cutoff).cloned().collect::<Vec<_>>();

        let state_hash_at_window_start_parent = self
            .materialize_view_at_block(window_start_parent_block_hash)
            .map(|view| view.state_hash)
            .or_else(|| self.state_hash_by_block.get(&window_start_parent_block_hash).copied());

        Ok(AtomicTokenSnapshot {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            protocol_version: self.protocol_version,
            network_id: self.network_id.clone(),
            at_block_hash,
            at_daa_score,
            state_hash_at_fp: view.state_hash,
            state_hash_at_window_start_parent,
            window_start_block_hash,
            window_start_parent_block_hash,
            window_end_block_hash,
            state: AtomicTokenSnapshotState {
                assets: view.assets,
                balances: view.balances,
                nonces: view.nonces,
                anchor_counts: view.anchor_counts,
                processed_ops: view.processed_ops,
                state_hash_by_block,
                event_sequence_by_block,
                applied_chain_order,
                next_event_sequence: view.event_sequence_cutoff,
                events,
            },
            journals_in_window,
        })
    }

    #[cfg(test)]
    pub fn export_snapshot_consuming(
        mut self,
        at_block_hash: BlockHash,
        at_daa_score: u64,
        window_start_parent_block_hash: BlockHash,
        window_blocks: &[BlockHash],
    ) -> AtomicTokenResult<AtomicTokenSnapshot> {
        if window_blocks.is_empty() {
            return Err(AtomicTokenError::Processing("cannot export snapshot with empty rollback window".to_string()));
        }

        let target_index = self.applied_chain_order.iter().position(|hash| *hash == at_block_hash).ok_or_else(|| {
            AtomicTokenError::Processing(format!("snapshot export failed: at_block_hash `{at_block_hash}` not found in applied chain"))
        })?;
        let window_start_block_hash = window_blocks[0];
        let window_end_block_hash = *window_blocks.last().unwrap();
        if window_end_block_hash != at_block_hash {
            return Err(AtomicTokenError::Processing("snapshot export window end must match snapshot at_block_hash".to_string()));
        }
        let window_start_index =
            self.applied_chain_order.iter().position(|hash| *hash == window_start_block_hash).ok_or_else(|| {
                AtomicTokenError::Processing(format!(
                    "snapshot export failed: window_start_block_hash `{window_start_block_hash}` not found in applied chain"
                ))
            })?;
        if window_start_index > target_index {
            return Err(AtomicTokenError::Processing(
                "snapshot export failed: window_start_block_hash appears after at_block_hash".to_string(),
            ));
        }
        let expected_window = &self.applied_chain_order[window_start_index..=target_index];
        if expected_window != window_blocks {
            return Err(AtomicTokenError::Processing(
                "snapshot export failed: rollback window is not a contiguous canonical chain segment".to_string(),
            ));
        }
        if window_start_index > 0 && self.applied_chain_order[window_start_index - 1] != window_start_parent_block_hash {
            return Err(AtomicTokenError::Processing(
                "snapshot export failed: window_start_parent_block_hash does not match canonical chain parent".to_string(),
            ));
        }

        let applied_chain_order = self.applied_chain_order[window_start_index..=target_index].to_vec();
        let mut state_hash_by_block = HashMap::with_capacity(applied_chain_order.len());
        let mut event_sequence_by_block = HashMap::with_capacity(applied_chain_order.len());
        for block_hash in applied_chain_order.iter().copied() {
            let state_hash = self.state_hash_by_block.get(&block_hash).copied().ok_or_else(|| {
                AtomicTokenError::Processing(format!("snapshot export failed: missing state hash checkpoint for block `{block_hash}`"))
            })?;
            let event_sequence = self.event_sequence_by_block.get(&block_hash).copied().ok_or_else(|| {
                AtomicTokenError::Processing(format!(
                    "snapshot export failed: missing event sequence checkpoint for block `{block_hash}`"
                ))
            })?;
            state_hash_by_block.insert(block_hash, state_hash);
            event_sequence_by_block.insert(block_hash, event_sequence);
        }

        let mut journals_in_window = Vec::with_capacity(window_blocks.len());
        for block_hash in window_blocks.iter().copied() {
            let journal = self.block_journals.get(&block_hash).cloned().ok_or_else(|| {
                AtomicTokenError::Processing(format!("missing block journal in snapshot window for block `{block_hash}`"))
            })?;
            journals_in_window.push((block_hash, journal));
        }

        for block_hash in self.applied_chain_order[target_index + 1..].iter().rev().copied().collect::<Vec<_>>() {
            self.rollback_block_internal(block_hash, false).map_err(|_| {
                AtomicTokenError::Processing(format!(
                    "snapshot export failed: missing journal while rolling back block `{block_hash}`"
                ))
            })?;
        }

        let state_hash_at_fp = self.compute_state_hash();
        if state_hash_by_block.get(&at_block_hash).copied() != Some(state_hash_at_fp) {
            return Err(AtomicTokenError::Processing(
                "snapshot export failed: retained state hash checkpoint does not match materialized anchor state".to_string(),
            ));
        }
        let state_hash_at_window_start_parent = self.state_hash_by_block.get(&window_start_parent_block_hash).copied();
        let next_event_sequence = self.event_sequence_by_block.get(&at_block_hash).copied().unwrap_or(self.next_event_sequence);
        self.events.retain(|event| event.sequence <= next_event_sequence);
        self.rebuild_event_id_index();

        Ok(AtomicTokenSnapshot {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            protocol_version: self.protocol_version,
            network_id: self.network_id,
            at_block_hash,
            at_daa_score,
            state_hash_at_fp,
            state_hash_at_window_start_parent,
            window_start_block_hash,
            window_start_parent_block_hash,
            window_end_block_hash,
            state: AtomicTokenSnapshotState {
                assets: self.assets,
                balances: self.balances,
                nonces: self.nonces,
                anchor_counts: self.anchor_counts,
                processed_ops: self.processed_ops,
                state_hash_by_block,
                event_sequence_by_block,
                applied_chain_order,
                next_event_sequence,
                events: self.events,
            },
            journals_in_window,
        })
    }

    #[cfg(test)]
    pub fn import_snapshot(&mut self, snapshot: AtomicTokenSnapshot) -> AtomicTokenResult<()> {
        let expected_state_hash_at_fp = snapshot.state_hash_at_fp;
        if snapshot.schema_version != SNAPSHOT_SCHEMA_VERSION {
            return Err(AtomicTokenError::SnapshotSchemaMismatch {
                expected: SNAPSHOT_SCHEMA_VERSION,
                actual: snapshot.schema_version,
            });
        }
        if snapshot.protocol_version != self.protocol_version {
            return Err(AtomicTokenError::SnapshotProtocolMismatch {
                expected: self.protocol_version,
                actual: snapshot.protocol_version,
            });
        }
        if snapshot.network_id != self.network_id {
            return Err(AtomicTokenError::SnapshotNetworkMismatch { expected: self.network_id.clone(), actual: snapshot.network_id });
        }
        if snapshot.window_end_block_hash != snapshot.at_block_hash {
            return Err(AtomicTokenError::Processing(
                "snapshot import failed: window_end_block_hash must equal at_block_hash".to_string(),
            ));
        }
        if snapshot.state.applied_chain_order.last().copied() != Some(snapshot.at_block_hash) {
            return Err(AtomicTokenError::Processing(
                "snapshot import failed: applied_chain_order must end at at_block_hash".to_string(),
            ));
        }
        Self::validate_snapshot_chain_indexes(&snapshot.state)?;
        if snapshot.state.state_hash_by_block.get(&snapshot.at_block_hash).copied() != Some(expected_state_hash_at_fp) {
            return Err(AtomicTokenError::Processing(
                "snapshot import failed: state_hash_by_block does not match state_hash_at_fp for at_block_hash".to_string(),
            ));
        }
        if snapshot.state.events.iter().any(|event| event.sequence > snapshot.state.next_event_sequence) {
            return Err(AtomicTokenError::Processing(
                "snapshot import failed: event sequence exceeds next_event_sequence".to_string(),
            ));
        }
        let window_start_index =
            snapshot.state.applied_chain_order.iter().position(|hash| *hash == snapshot.window_start_block_hash).ok_or_else(|| {
                AtomicTokenError::Processing(format!(
                    "snapshot import failed: window_start_block_hash `{}` not found in applied_chain_order",
                    snapshot.window_start_block_hash
                ))
            })?;
        let expected_window_len = snapshot.state.applied_chain_order.len() - window_start_index;
        if snapshot.journals_in_window.len() != expected_window_len {
            return Err(AtomicTokenError::Processing(format!(
                "snapshot import failed: journals_in_window length mismatch ({} != {})",
                snapshot.journals_in_window.len(),
                expected_window_len
            )));
        }
        for (offset, (block_hash, _)) in snapshot.journals_in_window.iter().enumerate() {
            let expected_hash = snapshot.state.applied_chain_order[window_start_index + offset];
            if *block_hash != expected_hash {
                return Err(AtomicTokenError::Processing(
                    "snapshot import failed: journals_in_window order does not match canonical chain path".to_string(),
                ));
            }
        }

        let AtomicTokenSnapshot { state, journals_in_window, .. } = snapshot;
        let AtomicTokenSnapshotState {
            assets,
            balances,
            nonces,
            anchor_counts,
            processed_ops,
            state_hash_by_block,
            event_sequence_by_block,
            applied_chain_order,
            next_event_sequence: _,
            events: _,
        } = state;
        Self::validate_snapshot_processed_ops(&processed_ops, &journals_in_window)?;

        let mut trusted_state_hash_by_block = HashMap::with_capacity(applied_chain_order.len());
        let mut trusted_event_sequence_by_block = HashMap::with_capacity(applied_chain_order.len());
        for block_hash in applied_chain_order.iter().copied() {
            let state_hash = state_hash_by_block.get(&block_hash).copied().ok_or_else(|| {
                AtomicTokenError::Processing(format!(
                    "snapshot import failed: missing state_hash_by_block entry for block `{block_hash}`"
                ))
            })?;
            let event_sequence = event_sequence_by_block.get(&block_hash).copied().ok_or_else(|| {
                AtomicTokenError::Processing(format!(
                    "snapshot import failed: missing event_sequence_by_block entry for block `{block_hash}`"
                ))
            })?;
            trusted_state_hash_by_block.insert(block_hash, state_hash);
            trusted_event_sequence_by_block.insert(block_hash, event_sequence);
        }

        self.assets = assets;
        self.balances = balances;
        self.nonces = nonces;
        self.anchor_counts = anchor_counts;
        self.processed_ops = processed_ops;
        self.state_hash_by_block = trusted_state_hash_by_block;
        self.event_sequence_by_block = trusted_event_sequence_by_block;
        self.applied_chain_order = applied_chain_order;
        self.next_event_sequence = 0;
        self.events = Vec::new();
        self.event_ids.clear();
        self.block_journals = journals_in_window.into_iter().collect();
        self.rebuild_liquidity_vault_outpoint_index();
        self.rebuild_known_owner_address_cache();
        if self.compute_state_hash() != expected_state_hash_at_fp {
            return Err(AtomicTokenError::Processing(
                "snapshot import failed: state hash mismatch at snapshot at_block_hash".to_string(),
            ));
        }
        self.degraded = false;
        self.live_correct = false;
        Ok(())
    }

    #[cfg(test)]
    pub fn rollback_snapshot_window_to_parent(&mut self, window_start_block_hash: BlockHash) -> AtomicTokenResult<()> {
        let mut found_window_start = false;
        while let Some(last_applied) = self.applied_chain_order.last().copied() {
            self.rollback_block_internal(last_applied, false).map_err(|_| {
                AtomicTokenError::Processing(format!(
                    "snapshot import failed: missing journal while rolling back block `{last_applied}`"
                ))
            })?;
            if last_applied == window_start_block_hash {
                found_window_start = true;
                break;
            }
        }

        if !found_window_start {
            return Err(AtomicTokenError::Processing(format!(
                "snapshot import failed: window_start_block_hash `{window_start_block_hash}` not found in applied chain order"
            )));
        }

        Ok(())
    }

    pub fn rollback_snapshot_window_to_parent_persisted(&mut self, window_start_block_hash: BlockHash) -> AtomicTokenResult<()> {
        let rollback_total = self
            .applied_chain_order
            .iter()
            .rev()
            .position(|hash| *hash == window_start_block_hash)
            .map(|index| index + 1)
            .unwrap_or(self.applied_chain_order.len());
        let should_log_progress = rollback_total >= 1024;
        let mut rolled_back = 0usize;
        let mut last_log = Instant::now();
        let mut found_window_start = false;
        while let Some(last_applied) = self.applied_chain_order.last().copied() {
            let journal = self.rollback_block_internal(last_applied, false).map_err(|_| {
                AtomicTokenError::Processing(format!(
                    "snapshot import failed: missing journal while rolling back block `{last_applied}`"
                ))
            })?;
            self.commit_rollback_to_store(last_applied, &journal, &[])?;
            rolled_back += 1;
            if should_log_progress && last_log.elapsed() >= LONG_ATOMIC_REPLAY_LOG_INTERVAL {
                info!("[{IDENT}] Cryptix Atomic retained replay rollback progress: {}/{} block(s)", rolled_back, rollback_total);
                last_log = Instant::now();
            }
            if last_applied == window_start_block_hash {
                found_window_start = true;
                break;
            }
        }

        if !found_window_start {
            return Err(AtomicTokenError::Processing(format!(
                "snapshot import failed: window_start_block_hash `{window_start_block_hash}` not found in applied chain order"
            )));
        }

        Ok(())
    }

    pub fn rollback_to_block_persisted(&mut self, target_block_hash: BlockHash) -> AtomicTokenResult<()> {
        let mut found_target = false;
        while let Some(last_applied) = self.applied_chain_order.last().copied() {
            if last_applied == target_block_hash {
                found_target = true;
                break;
            }
            let journal = self.rollback_block_internal(last_applied, false).map_err(|_| {
                AtomicTokenError::Processing(format!(
                    "snapshot export failed: missing journal while rolling back block `{last_applied}`"
                ))
            })?;
            self.commit_rollback_to_store(last_applied, &journal, &[])?;
        }

        if !found_target {
            return Err(AtomicTokenError::Processing(format!(
                "snapshot export failed: target block `{target_block_hash}` not found in applied chain order"
            )));
        }

        Ok(())
    }

    #[cfg(test)]
    fn validate_snapshot_chain_indexes(state: &AtomicTokenSnapshotState) -> AtomicTokenResult<()> {
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

        Ok(())
    }

    #[cfg(test)]
    fn validate_snapshot_processed_ops(
        processed_ops: &HashMap<BlockHash, ProcessedOp>,
        journals_in_window: &[(BlockHash, BlockJournal)],
    ) -> AtomicTokenResult<()> {
        let mut seen_window_txids = HashSet::new();
        let mut accepting_blocks_in_window = HashSet::new();
        for (accepting_block_hash, journal) in journals_in_window.iter() {
            accepting_blocks_in_window.insert(*accepting_block_hash);
            if journal.added_processed_ops.len() != journal.tx_results.len() {
                return Err(AtomicTokenError::Processing(format!(
                    "snapshot import failed: journal tx-result length mismatch for block `{accepting_block_hash}`"
                )));
            }

            for (txid, tx_result) in journal.added_processed_ops.iter().copied().zip(journal.tx_results.iter()) {
                if !seen_window_txids.insert(txid) {
                    return Err(AtomicTokenError::Processing(format!(
                        "snapshot import failed: duplicate processed txid `{txid}` in rollback window journals"
                    )));
                }
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
                match processed_ops.get(&txid) {
                    Some(actual) if *actual == expected => {}
                    Some(_) => {
                        return Err(AtomicTokenError::Processing(format!(
                            "snapshot import failed: processed txid `{txid}` does not match rollback window journal"
                        )));
                    }
                    None => {
                        return Err(AtomicTokenError::Processing(format!(
                            "snapshot import failed: processed txid `{txid}` is missing from snapshot processed_ops"
                        )));
                    }
                }
            }
        }
        if processed_ops
            .iter()
            .any(|(txid, op)| accepting_blocks_in_window.contains(&op.accepting_block_hash) && !seen_window_txids.contains(txid))
        {
            return Err(AtomicTokenError::Processing(
                "snapshot import failed: processed_ops contains entries outside the rollback window".to_string(),
            ));
        }
        Ok(())
    }

    pub fn compute_state_hash(&self) -> [u8; 32] {
        self.compute_state_hash_canonical()
    }

    fn compute_state_hash_for_view(&self, view: AtomicTokenReadView) -> [u8; 32] {
        let state = Self {
            protocol_version: self.protocol_version,
            network_id: self.network_id.clone(),
            degraded: false,
            live_correct: false,
            assets: view.assets,
            balances: view.balances,
            nonces: view.nonces,
            anchor_counts: view.anchor_counts,
            processed_ops: view.processed_ops,
            block_journals: Default::default(),
            state_hash_by_block: Default::default(),
            event_sequence_by_block: Default::default(),
            applied_chain_order: Default::default(),
            next_event_sequence: 0,
            events: Default::default(),
            event_ids: Default::default(),
            payload_hf_activation_daa_score: self.payload_hf_activation_daa_score,
            liquidity_vault_outpoints: Default::default(),
            known_owner_addresses: Default::default(),
            balances_by_owner: Default::default(),
            holders_by_asset: Default::default(),
            state_store: None,
            deleted_assets: Default::default(),
            deleted_balances: Default::default(),
            deleted_nonces: Default::default(),
            deleted_anchor_counts: Default::default(),
            deleted_processed_ops: Default::default(),
        };
        state.compute_state_hash_canonical()
    }

    fn compute_state_hash_canonical(&self) -> [u8; 32] {
        if self.assets.is_empty()
            && self.balances.is_empty()
            && self.nonces.is_empty()
            && self.anchor_counts.is_empty()
            && self.processed_ops.is_empty()
            && self.deleted_assets.is_empty()
            && self.deleted_balances.is_empty()
            && self.deleted_nonces.is_empty()
            && self.deleted_anchor_counts.is_empty()
            && self.deleted_processed_ops.is_empty()
        {
            if let Some(root) = self.state_store.as_ref().and_then(|store| store.current_root().ok().flatten()) {
                return root;
            }
        }

        compute_state_root_from_parts(&self.assets, &self.balances, &self.nonces, &self.anchor_counts)
    }
}

fn map_liquidity_math_error(err: LiquidityMathError) -> NoopReason {
    match err {
        LiquidityMathError::Overflow => NoopReason::SupplyOverflow,
        LiquidityMathError::InvalidInput => NoopReason::InvalidAmount,
        LiquidityMathError::InvalidState => NoopReason::InternalMalformedAcceptance,
        LiquidityMathError::ZeroOutput => NoopReason::ZeroOutput,
    }
}

fn is_replay_integrity_failure(reason: NoopReason) -> bool {
    // We only replay transactions consensus already accepted into the virtual chain.
    // Any CAT semantic failure here means the index view has diverged from consensus
    // or the persisted V2 state is stale/corrupt, so fail closed instead of reporting
    // a healthy but submit-unsafe token state.
    !matches!(reason, NoopReason::None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::liquidity_math::INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI;
    use crate::payload::TokenOpCode;
    use cryptix_consensus_core::{
        constants::TX_VERSION,
        subnets::{SUBNETWORK_ID_COINBASE, SUBNETWORK_ID_PAYLOAD},
        tx::{ScriptVec, TransactionInput, TransactionOutput},
    };
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn test_script(seed: u8) -> ScriptPublicKey {
        let mut bytes = vec![0x20];
        bytes.extend((0..32).map(|i| seed.wrapping_add(i)));
        bytes.push(0xAC);
        ScriptPublicKey::new(0, ScriptVec::from_slice(&bytes))
    }

    fn hash_bytes(hash: BlockHash) -> [u8; 32] {
        hash.as_bytes()
    }

    fn owner_id(state: &AtomicTokenState, script: &ScriptPublicKey) -> [u8; 32] {
        state.owner_id_from_script(script).expect("owner id should derive")
    }

    fn base_header(op: TokenOpCode, auth_input_index: u16, nonce: u64) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"CAT");
        payload.push(1);
        payload.push(op as u8);
        payload.push(0);
        payload.extend_from_slice(&auth_input_index.to_le_bytes());
        payload.extend_from_slice(&nonce.to_le_bytes());
        payload
    }

    fn payload_create_asset(
        auth_input_index: u16,
        nonce: u64,
        decimals: u8,
        mint_authority_owner_id: [u8; 32],
        name: &[u8],
        symbol: &[u8],
        metadata: &[u8],
    ) -> Vec<u8> {
        let mut payload = base_header(TokenOpCode::CreateAsset, auth_input_index, nonce);
        payload.push(CURRENT_TOKEN_VERSION);
        payload.push(decimals);
        payload.push(SupplyMode::Uncapped as u8);
        payload.extend_from_slice(&0u128.to_le_bytes());
        payload.extend_from_slice(&mint_authority_owner_id);
        payload.push(name.len() as u8);
        payload.push(symbol.len() as u8);
        payload.extend_from_slice(&(metadata.len() as u16).to_le_bytes());
        payload.extend_from_slice(name);
        payload.extend_from_slice(symbol);
        payload.extend_from_slice(metadata);
        payload
    }

    fn payload_mint(auth_input_index: u16, nonce: u64, asset_id: [u8; 32], to_owner_id: [u8; 32], amount: u128) -> Vec<u8> {
        let mut payload = base_header(TokenOpCode::Mint, auth_input_index, nonce);
        payload.extend_from_slice(&asset_id);
        payload.extend_from_slice(&to_owner_id);
        payload.extend_from_slice(&amount.to_le_bytes());
        payload
    }

    fn payload_transfer(auth_input_index: u16, nonce: u64, asset_id: [u8; 32], to_owner_id: [u8; 32], amount: u128) -> Vec<u8> {
        let mut payload = base_header(TokenOpCode::Transfer, auth_input_index, nonce);
        payload.extend_from_slice(&asset_id);
        payload.extend_from_slice(&to_owner_id);
        payload.extend_from_slice(&amount.to_le_bytes());
        payload
    }

    fn payload_burn(auth_input_index: u16, nonce: u64, asset_id: [u8; 32], amount: u128) -> Vec<u8> {
        let mut payload = base_header(TokenOpCode::Burn, auth_input_index, nonce);
        payload.extend_from_slice(&asset_id);
        payload.extend_from_slice(&amount.to_le_bytes());
        payload
    }

    fn payload_create_liquidity(
        auth_input_index: u16,
        nonce: u64,
        max_supply: u128,
        seed_reserve_sompi: u64,
        launch_buy_sompi: u64,
        launch_buy_min_token_out: u128,
    ) -> Vec<u8> {
        let mut payload = base_header(TokenOpCode::CreateLiquidityAsset, auth_input_index, nonce);
        payload.push(CURRENT_TOKEN_VERSION);
        payload.push(CURRENT_LIQUIDITY_CURVE_VERSION);
        payload.push(0);
        payload.extend_from_slice(&max_supply.to_le_bytes());
        payload.push(4);
        payload.push(3);
        payload.extend_from_slice(&0u16.to_le_bytes());
        payload.extend_from_slice(b"Pool");
        payload.extend_from_slice(b"POL");
        payload.extend_from_slice(&seed_reserve_sompi.to_le_bytes());
        payload.extend_from_slice(&0u16.to_le_bytes());
        payload.push(0);
        payload.extend_from_slice(&launch_buy_sompi.to_le_bytes());
        payload.extend_from_slice(&launch_buy_min_token_out.to_le_bytes());
        payload
    }

    fn payload_buy_liquidity(
        auth_input_index: u16,
        nonce: u64,
        asset_id: [u8; 32],
        expected_pool_nonce: u64,
        cpay_in_sompi: u64,
        min_token_out: u128,
    ) -> Vec<u8> {
        let mut payload = base_header(TokenOpCode::BuyLiquidityExactIn, auth_input_index, nonce);
        payload.extend_from_slice(&asset_id);
        payload.extend_from_slice(&expected_pool_nonce.to_le_bytes());
        payload.extend_from_slice(&cpay_in_sompi.to_le_bytes());
        payload.extend_from_slice(&min_token_out.to_le_bytes());
        payload
    }

    fn liquidity_vault_script() -> ScriptPublicKey {
        ScriptPublicKey::new(0, ScriptVec::from_slice(&[0x04, b'C', b'L', b'V', b'1', 0x75, 0x51]))
    }

    fn token_tx(previous_outpoint: TransactionOutpoint, output_script: ScriptPublicKey, payload: Vec<u8>) -> Transaction {
        let input = TransactionInput::new(previous_outpoint, vec![], 0, 1);
        let output = TransactionOutput::new(1, output_script);
        let mut tx = Transaction::new(TX_VERSION, vec![input], vec![output], 0, SUBNETWORK_ID_PAYLOAD, 0, payload);
        tx.finalize();
        tx
    }

    fn coinbase_tx(output_script: ScriptPublicKey) -> Transaction {
        let output = TransactionOutput::new(1, output_script);
        let mut tx = Transaction::new(TX_VERSION, vec![], vec![output], 0, SUBNETWORK_ID_COINBASE, 0, vec![0u8; 20]);
        tx.finalize();
        tx
    }

    fn tx_with_inputs_outputs(
        inputs: Vec<(TransactionOutpoint, u8)>,
        outputs: Vec<TransactionOutput>,
        payload: Vec<u8>,
    ) -> Transaction {
        let inputs = inputs
            .into_iter()
            .map(|(previous_outpoint, sig_op_count)| TransactionInput::new(previous_outpoint, vec![], 0, sig_op_count))
            .collect();
        let mut tx = Transaction::new(TX_VERSION, inputs, outputs, 0, SUBNETWORK_ID_PAYLOAD, 0, payload);
        tx.finalize();
        tx
    }

    fn tx_ref(tx: Transaction, source_block_hash: BlockHash, tx_index: u32, acceptance_entry_position: u32) -> CanonicalTxRef {
        tx_ref_with_source_metadata(tx, source_block_hash, 0, 0, tx_index, acceptance_entry_position)
    }

    fn tx_ref_with_source_metadata(
        tx: Transaction,
        source_block_hash: BlockHash,
        source_block_daa_score: u64,
        source_block_time: u64,
        tx_index: u32,
        acceptance_entry_position: u32,
    ) -> CanonicalTxRef {
        let txid = tx.id();
        CanonicalTxRef { txid, source_block_hash, source_block_daa_score, source_block_time, tx_index, acceptance_entry_position, tx }
    }

    fn apply_block(
        state: &mut AtomicTokenState,
        accepting_block_hash: BlockHash,
        refs: Vec<CanonicalTxRef>,
        auth_inputs: &HashMap<TransactionOutpoint, UtxoEntry>,
    ) {
        let mut journal = JournalBuilder::default();
        for (ordinal, tx_ref) in refs.iter().enumerate() {
            let apply_anchor_deltas =
                state.apply_transaction(accepting_block_hash, 0, 0, tx_ref, ordinal as u32, auth_inputs, &mut journal);
            if apply_anchor_deltas {
                state.apply_anchor_deltas_for_tx(&tx_ref.tx, auth_inputs, &mut journal);
            }
        }
        state.block_journals.insert(accepting_block_hash, journal.into_block_journal());
        state.state_hash_by_block.insert(accepting_block_hash, state.compute_state_hash());
        state.event_sequence_by_block.insert(accepting_block_hash, state.next_event_sequence);
        state.applied_chain_order.push(accepting_block_hash);
    }

    fn apply_block_and_commit(
        state: &mut AtomicTokenState,
        accepting_block_hash: BlockHash,
        refs: Vec<CanonicalTxRef>,
        auth_inputs: &HashMap<TransactionOutpoint, UtxoEntry>,
    ) {
        let old_event_len = state.events.len();
        let mut journal = JournalBuilder::default();
        for (ordinal, tx_ref) in refs.iter().enumerate() {
            let apply_anchor_deltas =
                state.apply_transaction(accepting_block_hash, 0, 0, tx_ref, ordinal as u32, auth_inputs, &mut journal);
            if apply_anchor_deltas {
                state.apply_anchor_deltas_for_tx(&tx_ref.tx, auth_inputs, &mut journal);
            }
        }
        let block_journal = journal.into_block_journal();
        let event_sequence = state.next_event_sequence;
        let chain_index = state.applied_chain_order.len() as u64;
        let new_events = state.events[old_event_len..].to_vec();
        let state_hash = state
            .commit_applied_block_to_store(accepting_block_hash, &block_journal, chain_index, event_sequence, &new_events)
            .expect("commit applied block to V2 store")
            .unwrap_or_else(|| state.compute_state_hash());
        state.block_journals.insert(accepting_block_hash, block_journal);
        state.state_hash_by_block.insert(accepting_block_hash, state_hash);
        state.event_sequence_by_block.insert(accepting_block_hash, event_sequence);
        state.applied_chain_order.push(accepting_block_hash);
    }

    fn unique_temp_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        std::env::temp_dir().join(format!("cryptix-atomic-state-{name}-{}-{nonce}", std::process::id()))
    }

    #[test]
    fn balance_indices_track_balance_lifecycle_and_rebuild() {
        let mut state = AtomicTokenState::new(1, "cryptix-simnet".to_string());
        let asset_a = [0x11; 32];
        let asset_b = [0x22; 32];
        let owner_a = [0x33; 32];
        let owner_b = [0x44; 32];

        state.set_balance_amount(BalanceKey { asset_id: asset_a, owner_id: owner_a }, 100);
        state.set_balance_amount(BalanceKey { asset_id: asset_b, owner_id: owner_a }, 200);
        state.set_balance_amount(BalanceKey { asset_id: asset_a, owner_id: owner_b }, 300);

        let mut owner_balances = state.indexed_balances_by_owner(owner_a, false);
        owner_balances.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(owner_balances, vec![(asset_a, 100, None), (asset_b, 200, None)]);

        let mut asset_holders = state.indexed_holders_by_asset(asset_a);
        asset_holders.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(asset_holders, vec![(owner_a, 100), (owner_b, 300)]);

        state.set_balance_amount(BalanceKey { asset_id: asset_a, owner_id: owner_a }, 0);
        assert_eq!(state.indexed_balances_by_owner(owner_a, false), vec![(asset_b, 200, None)]);
        assert_eq!(state.indexed_holders_by_asset(asset_a), vec![(owner_b, 300)]);

        state.balances.insert(BalanceKey { asset_id: asset_a, owner_id: owner_a }, 400);
        state.rebuild_runtime_caches();
        let mut rebuilt_holders = state.indexed_holders_by_asset(asset_a);
        rebuilt_holders.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(rebuilt_holders, vec![(owner_a, 400), (owner_b, 300)]);
    }

    #[test]
    fn rollback_restores_balance_indices() {
        let mut state = AtomicTokenState::new(1, "cryptix-simnet".to_string());
        let asset_id = [0x55; 32];
        let owner_id = [0x66; 32];
        let key = BalanceKey { asset_id, owner_id };
        state.set_balance_amount(key, 100);

        let block_hash = BlockHash::from_u64_word(123);
        let mut journal = JournalBuilder::default();
        state.record_balance_before(key, &mut journal);
        state.set_balance_amount(key, 0);
        state.block_journals.insert(block_hash, journal.into_block_journal());
        state.state_hash_by_block.insert(block_hash, state.compute_state_hash());
        state.event_sequence_by_block.insert(block_hash, state.next_event_sequence);
        state.applied_chain_order.push(block_hash);

        assert!(state.indexed_balances_by_owner(owner_id, false).is_empty());
        assert!(state.indexed_holders_by_asset(asset_id).is_empty());

        state.rollback_block(block_hash).expect("rollback should restore recorded balance");

        assert_eq!(state.get_balance(asset_id, owner_id), 100);
        assert_eq!(state.indexed_balances_by_owner(owner_id, false), vec![(asset_id, 100, None)]);
        assert_eq!(state.indexed_holders_by_asset(asset_id), vec![(owner_id, 100)]);
    }

    #[test]
    fn pre_hf_cat_payloads_are_ignored() {
        let mut state = AtomicTokenState::new(1, "cryptix-simnet".to_string());
        state.set_payload_hf_activation_daa_score(10);

        let owner_script = test_script(7);
        let owner_id = owner_id(&state, &owner_script);
        let outpoint = TransactionOutpoint::new(BlockHash::from_u64_word(1234), 0);
        let payload = payload_create_asset(0, 1, 8, owner_id, b"PreHF", b"PHF", b"");
        let tx = token_tx(outpoint, owner_script.clone(), payload);
        let txid = tx.id();

        let mut auth_inputs = HashMap::new();
        auth_inputs.insert(outpoint, UtxoEntry::new(1000, owner_script, 0, false));

        apply_block(&mut state, BlockHash::from_u64_word(4321), vec![tx_ref(tx, BlockHash::from_u64_word(4000), 0, 0)], &auth_inputs);

        assert!(!state.processed_ops.contains_key(&txid));
        assert!(!state.assets.contains_key(&hash_bytes(txid)));
        assert_eq!(state.next_event_sequence, 0);
    }

    #[test]
    fn accepted_coinbase_does_not_mutate_token_anchor_counts() {
        let mut state = AtomicTokenState::new(1, "cryptix-simnet".to_string());
        state.set_payload_hf_activation_daa_score(0);

        let owner_script = test_script(0xC1);
        let owner_id = owner_id(&state, &owner_script);
        let before = state.compute_state_hash();
        let tx = coinbase_tx(owner_script);

        apply_block(
            &mut state,
            BlockHash::from_u64_word(8101),
            vec![tx_ref(tx, BlockHash::from_u64_word(8100), 0, 0)],
            &HashMap::new(),
        );

        assert_eq!(state.get_anchor_count(owner_id), 0, "coinbase outputs must not become CAT anchor counts");
        assert_eq!(state.compute_state_hash(), before, "coinbase-only acceptance must not change token checkpoint hash");
        assert_eq!(state.next_event_sequence, 0);
    }

    #[test]
    fn nonce_overflow_is_rejected_before_index_mutation() {
        let mut state = AtomicTokenState::new(1, "cryptix-simnet".to_string());
        let owner_script = test_script(8);
        let owner_id = owner_id(&state, &owner_script);
        let outpoint = TransactionOutpoint::new(BlockHash::from_u64_word(2234), 0);
        state.nonces.insert(NonceKey::owner(owner_id), u64::MAX);

        let payload = payload_create_asset(0, u64::MAX, 8, owner_id, b"Overflow", b"OVF", b"");
        let tx = token_tx(outpoint, owner_script.clone(), payload);
        let txid = tx.id();
        let mut auth_inputs = HashMap::new();
        auth_inputs.insert(outpoint, UtxoEntry::new(1000, owner_script, 0, false));

        apply_block(&mut state, BlockHash::from_u64_word(5321), vec![tx_ref(tx, BlockHash::from_u64_word(5000), 0, 0)], &auth_inputs);

        assert!(state.degraded, "accepted nonce-overflow CAT op must fail closed");
        assert!(!state.assets.contains_key(&hash_bytes(txid)), "overflowing nonce must be rejected before asset mutation");
        assert_eq!(state.get_owner_nonce(owner_id), u64::MAX);
        let processed = state.processed_ops.get(&txid).expect("overflowing tx should be recorded as noop");
        assert_eq!(processed.apply_status, ApplyStatus::Noop);
        assert_eq!(processed.noop_reason, NoopReason::InternalMalformedAcceptance);
    }

    #[test]
    fn stale_nonce_cat_op_degrades_indexer_because_accepted_cat_must_replay_cleanly() {
        let mut state = AtomicTokenState::new(1, "cryptix-simnet".to_string());
        let owner_script = test_script(9);
        let owner_id = owner_id(&state, &owner_script);
        let outpoint = TransactionOutpoint::new(BlockHash::from_u64_word(3234), 0);
        state.nonces.insert(NonceKey::owner(owner_id), 2);

        let payload = payload_create_asset(0, 1, 8, owner_id, b"Stale", b"STL", b"");
        let tx = token_tx(outpoint, owner_script.clone(), payload);
        let txid = tx.id();
        let mut auth_inputs = HashMap::new();
        auth_inputs.insert(outpoint, UtxoEntry::new(1000, owner_script, 0, false));

        apply_block(&mut state, BlockHash::from_u64_word(6321), vec![tx_ref(tx, BlockHash::from_u64_word(6000), 0, 0)], &auth_inputs);

        assert!(state.degraded, "accepted CAT replay failures must fail closed instead of leaving a stale healthy index");
        assert!(!state.assets.contains_key(&hash_bytes(txid)));
        assert_eq!(state.get_owner_nonce(owner_id), 2);
        let processed = state.processed_ops.get(&txid).expect("stale tx should be recorded as noop");
        assert_eq!(processed.apply_status, ApplyStatus::Noop);
        assert_eq!(processed.noop_reason, NoopReason::InternalMalformedAcceptance);
    }

    #[test]
    fn conformance_state_hash_golden_vector() {
        let mut state = AtomicTokenState::new(1, "cryptix-simnet".to_string());
        let asset_id = [0x11; 32];
        let owner = [0x22; 32];
        let creator = [0x33; 32];
        let authority = [0x44; 32];
        state.assets.insert(
            asset_id,
            TokenAsset {
                asset_id,
                creator_owner_id: creator,
                asset_class: TokenAssetClass::Standard,
                token_version: CURRENT_TOKEN_VERSION,
                mint_authority_owner_id: authority,
                decimals: 8,
                supply_mode: SupplyMode::Uncapped,
                max_supply: 0,
                total_supply: 900,
                name: b"Atomic".to_vec(),
                symbol: b"ATM".to_vec(),
                metadata: vec![0xA1, 0xB2],
                platform_tag: Vec::new(),
                created_block_hash: None,
                created_daa_score: None,
                created_at: None,
                liquidity: None,
            },
        );
        state.balances.insert(BalanceKey { asset_id, owner_id: owner }, 900);
        state.nonces.insert(NonceKey::owner(owner), 7);

        let hash = state.compute_state_hash();
        let hash_hex = to_hex(&hash);
        assert_eq!(hash_hex, "3ad3d91ea19241c69d6a5ab618798ba3086f20b66b38cc329fd913ce42efd8e9");
    }

    #[test]
    fn state_hash_commits_anchor_counts() {
        let mut state = AtomicTokenState::new(1, "cryptix-simnet".to_string());
        let owner = [0x55; 32];
        let before = state.compute_state_hash();
        state.anchor_counts.insert(owner, 2);
        let after = state.compute_state_hash();
        assert_ne!(before, after);
    }

    #[test]
    fn state_hash_ignores_liquidity_holder_addresses() {
        let mut state = AtomicTokenState::new(1, "cryptix-simnet".to_string());
        let asset_id = [0x10; 32];
        let creator_owner = [0x20; 32];
        let holder_owner = [0x30; 32];
        let mut holder_addresses = HashMap::new();
        holder_addresses.insert(holder_owner, LiquidityHolderAddressState { address_version: 0, address_payload: vec![0x44; 32] });

        state.assets.insert(
            asset_id,
            TokenAsset {
                asset_id,
                creator_owner_id: creator_owner,
                asset_class: TokenAssetClass::Liquidity,
                token_version: CURRENT_TOKEN_VERSION,
                mint_authority_owner_id: [0u8; 32],
                decimals: 8,
                supply_mode: SupplyMode::Capped,
                max_supply: 1_000,
                total_supply: 100,
                name: b"Liquidity".to_vec(),
                symbol: b"LIQ".to_vec(),
                metadata: vec![],
                platform_tag: Vec::new(),
                created_block_hash: None,
                created_daa_score: None,
                created_at: None,
                liquidity: Some(LiquidityPoolState {
                    pool_nonce: 1,
                    curve_version: CURRENT_LIQUIDITY_CURVE_VERSION,
                    curve_mode: DEFAULT_LIQUIDITY_CURVE_MODE,
                    individual_virtual_cpay_reserves_sompi: 0,
                    individual_virtual_token_multiplier_bps: 0,
                    real_cpay_reserves_sompi: 1_000_000,
                    real_token_reserves: 900,
                    virtual_cpay_reserves_sompi: INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI,
                    virtual_token_reserves: crate::liquidity_math::INITIAL_VIRTUAL_TOKEN_RESERVES,
                    unclaimed_fee_total_sompi: 0,
                    fee_bps: 0,
                    fee_recipients: vec![],
                    vault_outpoint: TransactionOutpoint::new(BlockHash::from_u64_word(7), 0),
                    vault_value_sompi: 1_000_000,
                    unlock_target_sompi: 0,
                    unlocked: true,
                    holder_addresses,
                }),
            },
        );
        let before = state.compute_state_hash();

        let asset = state.assets.get_mut(&asset_id).expect("asset should exist");
        let pool = asset.liquidity.as_mut().expect("liquidity should exist");
        pool.holder_addresses
            .insert(holder_owner, LiquidityHolderAddressState { address_version: 0, address_payload: vec![0x55; 32] });

        let after = state.compute_state_hash();
        assert_eq!(before, after);
    }

    #[test]
    fn state_hash_commits_asset_definition_metadata() {
        let mut state = AtomicTokenState::new(1, "cryptix-simnet".to_string());
        let asset_id = [0x11; 32];

        state.assets.insert(
            asset_id,
            TokenAsset {
                asset_id,
                creator_owner_id: [0x20; 32],
                asset_class: TokenAssetClass::Standard,
                token_version: CURRENT_TOKEN_VERSION,
                mint_authority_owner_id: [0x30; 32],
                decimals: 8,
                supply_mode: SupplyMode::Capped,
                max_supply: 1_000,
                total_supply: 100,
                name: b"Token".to_vec(),
                symbol: b"TKN".to_vec(),
                metadata: vec![0xAA],
                platform_tag: b"platform".to_vec(),
                created_block_hash: Some(BlockHash::from_u64_word(1)),
                created_daa_score: Some(10),
                created_at: Some(20),
                liquidity: None,
            },
        );

        let before = state.compute_state_hash();
        let asset = state.assets.get_mut(&asset_id).expect("asset should exist");
        asset.creator_owner_id = [0x21; 32];
        asset.decimals = 2;
        asset.name = b"Renamed".to_vec();
        asset.symbol = b"REN".to_vec();
        asset.metadata = vec![0xBB, 0xCC];
        asset.created_block_hash = Some(BlockHash::from_u64_word(2));
        asset.created_daa_score = Some(11);
        asset.created_at = Some(21);

        let after_metadata_change = state.compute_state_hash();
        assert_ne!(before, after_metadata_change);

        state.assets.get_mut(&asset_id).expect("asset should exist").total_supply += 1;
        let after_consensus_change = state.compute_state_hash();
        assert_ne!(before, after_consensus_change);
    }

    #[test]
    fn owner_id_accepts_standard_p2sh_script() {
        let state = AtomicTokenState::new(1, "cryptix-simnet".to_string());
        let script = cryptix_txscript::pay_to_script_hash_script(&[0x51]);

        assert_eq!(script.script().len(), 35);
        assert!(state.owner_id_from_script(&script).is_ok());
    }

    #[test]
    fn liquidity_create_and_buy_events_record_actual_outputs() {
        let mut state = AtomicTokenState::new(1, "cryptix-simnet".to_string());
        let owner_script = test_script(7);
        let owner = owner_id(&state, &owner_script);
        let max_supply = crate::liquidity_math::LIQUIDITY_TOKEN_SUPPLY_RAW;
        let seed_reserve_sompi = MIN_LIQUIDITY_SEED_RESERVE_SOMPI;
        let launch_buy_budget_sompi = 10 * MIN_LIQUIDITY_SEED_RESERVE_SOMPI;
        let launch_min = 1u128;
        let launch_token_out = cpmm_buy(
            max_supply,
            INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI,
            crate::liquidity_math::INITIAL_VIRTUAL_TOKEN_RESERVES,
            launch_buy_budget_sompi,
        )
        .expect("launch quote should work")
        .0;
        let launch_buy_sompi = crate::liquidity_math::min_gross_input_for_token_out(
            max_supply,
            INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI,
            crate::liquidity_math::INITIAL_VIRTUAL_TOKEN_RESERVES,
            launch_token_out,
            0,
        )
        .expect("canonical launch buy should calculate");

        let create_auth_outpoint = TransactionOutpoint::new(BlockHash::from_u64_word(1), 0);
        let create_payload = payload_create_liquidity(0, 1, max_supply, seed_reserve_sompi, launch_buy_sompi, launch_min);
        let create_tx = tx_with_inputs_outputs(
            vec![(create_auth_outpoint, 1)],
            vec![
                TransactionOutput::new(seed_reserve_sompi + launch_buy_sompi, liquidity_vault_script()),
                TransactionOutput::new(1, owner_script.clone()),
            ],
            create_payload,
        );
        let asset_id = hash_bytes(create_tx.id());

        let mut create_auth_inputs = HashMap::new();
        create_auth_inputs
            .insert(create_auth_outpoint, UtxoEntry::new(20 * MIN_LIQUIDITY_SEED_RESERVE_SOMPI, owner_script.clone(), 0, false));
        apply_block(
            &mut state,
            BlockHash::from_u64_word(10),
            vec![tx_ref(create_tx.clone(), BlockHash::from_u64_word(9), 0, 0)],
            &create_auth_inputs,
        );

        let create_event = state.events.last().expect("create event should be recorded");
        assert_eq!(create_event.details.op_type, Some(TokenOpCode::CreateLiquidityAsset));
        assert_eq!(create_event.details.to_owner_id, Some(owner));
        assert_eq!(create_event.details.amount, Some(launch_token_out));
        assert_ne!(create_event.details.amount, Some(launch_min));

        let pool = state.assets.get(&asset_id).and_then(|asset| asset.liquidity.clone()).expect("pool should exist");
        let buy_budget_sompi = 10 * MIN_LIQUIDITY_SEED_RESERVE_SOMPI;
        let buy_token_out =
            cpmm_buy(pool.real_token_reserves, pool.virtual_cpay_reserves_sompi, pool.virtual_token_reserves, buy_budget_sompi)
                .expect("buy quote should work")
                .0;
        let buy_in_sompi = crate::liquidity_math::min_gross_input_for_token_out(
            pool.real_token_reserves,
            pool.virtual_cpay_reserves_sompi,
            pool.virtual_token_reserves,
            buy_token_out,
            pool.fee_bps,
        )
        .expect("canonical buy should calculate");
        let buy_auth_outpoint = TransactionOutpoint::new(BlockHash::from_u64_word(2), 0);
        let buy_payload = payload_buy_liquidity(1, 1, asset_id, pool.pool_nonce, buy_in_sompi, 1);
        let buy_tx = tx_with_inputs_outputs(
            vec![(pool.vault_outpoint, 0), (buy_auth_outpoint, 1)],
            vec![
                TransactionOutput::new(pool.vault_value_sompi + buy_in_sompi, liquidity_vault_script()),
                TransactionOutput::new(1, owner_script.clone()),
            ],
            buy_payload,
        );

        let mut buy_auth_inputs = HashMap::new();
        buy_auth_inputs.insert(pool.vault_outpoint, UtxoEntry::new(pool.vault_value_sompi, liquidity_vault_script(), 0, false));
        buy_auth_inputs.insert(buy_auth_outpoint, UtxoEntry::new(20 * MIN_LIQUIDITY_SEED_RESERVE_SOMPI, owner_script, 0, false));
        apply_block(
            &mut state,
            BlockHash::from_u64_word(11),
            vec![tx_ref(buy_tx, BlockHash::from_u64_word(10), 0, 0)],
            &buy_auth_inputs,
        );

        let buy_event = state.events.last().expect("buy event should be recorded");
        assert_eq!(buy_event.details.op_type, Some(TokenOpCode::BuyLiquidityExactIn));
        assert_eq!(buy_event.details.amount, Some(buy_token_out));
        assert_ne!(buy_event.details.amount, Some(1));
    }

    #[test]
    fn liquidity_buy_reorg_restores_pool_vault_and_replays_alternative_branch() {
        let mut state = AtomicTokenState::new(1, "cryptix-simnet".to_string());
        let owner_script = test_script(70);
        let owner = owner_id(&state, &owner_script);
        let max_supply = crate::liquidity_math::LIQUIDITY_TOKEN_SUPPLY_RAW;
        let seed_reserve_sompi = MIN_LIQUIDITY_SEED_RESERVE_SOMPI;
        let launch_buy_budget_sompi = 10 * MIN_LIQUIDITY_SEED_RESERVE_SOMPI;
        let launch_token_out = cpmm_buy(
            max_supply,
            INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI,
            crate::liquidity_math::INITIAL_VIRTUAL_TOKEN_RESERVES,
            launch_buy_budget_sompi,
        )
        .expect("launch quote should work")
        .0;
        let launch_buy_sompi = crate::liquidity_math::min_gross_input_for_token_out(
            max_supply,
            INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI,
            crate::liquidity_math::INITIAL_VIRTUAL_TOKEN_RESERVES,
            launch_token_out,
            0,
        )
        .expect("canonical launch buy should calculate");

        let create_auth_outpoint = TransactionOutpoint::new(BlockHash::from_u64_word(7_000), 0);
        let create_tx = tx_with_inputs_outputs(
            vec![(create_auth_outpoint, 1)],
            vec![
                TransactionOutput::new(seed_reserve_sompi + launch_buy_sompi, liquidity_vault_script()),
                TransactionOutput::new(1, owner_script.clone()),
            ],
            payload_create_liquidity(0, 1, max_supply, seed_reserve_sompi, launch_buy_sompi, 1),
        );
        let asset_id = hash_bytes(create_tx.id());

        let mut create_auth_inputs = HashMap::new();
        create_auth_inputs
            .insert(create_auth_outpoint, UtxoEntry::new(20 * MIN_LIQUIDITY_SEED_RESERVE_SOMPI, owner_script.clone(), 0, false));
        let create_block = BlockHash::from_u64_word(7_010);
        apply_block(
            &mut state,
            create_block,
            vec![tx_ref(create_tx.clone(), BlockHash::from_u64_word(7_009), 0, 0)],
            &create_auth_inputs,
        );

        let base_state = state.clone();
        let base_hash = state.compute_state_hash();
        let base_pool = state.assets.get(&asset_id).and_then(|asset| asset.liquidity.clone()).expect("pool should exist");
        assert_eq!(state.find_liquidity_asset_by_vault_outpoint(base_pool.vault_outpoint).unwrap(), Some(asset_id));

        let build_buy = |pool: &LiquidityPoolState, tag: u64, budget: u64| {
            let token_out = cpmm_buy(pool.real_token_reserves, pool.virtual_cpay_reserves_sompi, pool.virtual_token_reserves, budget)
                .expect("buy quote should work")
                .0;
            let buy_in_sompi = crate::liquidity_math::min_gross_input_for_token_out(
                pool.real_token_reserves,
                pool.virtual_cpay_reserves_sompi,
                pool.virtual_token_reserves,
                token_out,
                pool.fee_bps,
            )
            .expect("canonical buy should calculate");
            let buy_auth_outpoint = TransactionOutpoint::new(BlockHash::from_u64_word(tag), 0);
            let buy_tx = tx_with_inputs_outputs(
                vec![(pool.vault_outpoint, 0), (buy_auth_outpoint, 1)],
                vec![
                    TransactionOutput::new(pool.vault_value_sompi + buy_in_sompi, liquidity_vault_script()),
                    TransactionOutput::new(1, owner_script.clone()),
                ],
                payload_buy_liquidity(1, 1, asset_id, pool.pool_nonce, buy_in_sompi, 1),
            );
            let mut auth_inputs = HashMap::new();
            auth_inputs.insert(pool.vault_outpoint, UtxoEntry::new(pool.vault_value_sompi, liquidity_vault_script(), 0, false));
            auth_inputs
                .insert(buy_auth_outpoint, UtxoEntry::new(20 * MIN_LIQUIDITY_SEED_RESERVE_SOMPI, owner_script.clone(), 0, false));
            (buy_tx, auth_inputs)
        };

        let (buy_a_tx, buy_a_auth_inputs) = build_buy(&base_pool, 7_020, 10 * MIN_LIQUIDITY_SEED_RESERVE_SOMPI);
        let block_a = BlockHash::from_u64_word(7_030);
        apply_block(&mut state, block_a, vec![tx_ref(buy_a_tx.clone(), BlockHash::from_u64_word(7_029), 0, 0)], &buy_a_auth_inputs);

        let branch_a_pool = state.assets.get(&asset_id).and_then(|asset| asset.liquidity.clone()).expect("pool should exist");
        assert_eq!(branch_a_pool.pool_nonce, base_pool.pool_nonce + 1);
        assert_ne!(branch_a_pool.vault_outpoint, base_pool.vault_outpoint);
        assert_eq!(state.find_liquidity_asset_by_vault_outpoint(branch_a_pool.vault_outpoint).unwrap(), Some(asset_id));

        state.rollback_block(block_a).expect("rollback branch A buy");
        let rolled_back_pool = state.assets.get(&asset_id).and_then(|asset| asset.liquidity.clone()).expect("pool should exist");
        assert_eq!(rolled_back_pool.pool_nonce, base_pool.pool_nonce);
        assert_eq!(rolled_back_pool.vault_outpoint, base_pool.vault_outpoint);
        assert_eq!(rolled_back_pool.vault_value_sompi, base_pool.vault_value_sompi);
        assert_eq!(rolled_back_pool.real_cpay_reserves_sompi, base_pool.real_cpay_reserves_sompi);
        assert_eq!(rolled_back_pool.real_token_reserves, base_pool.real_token_reserves);
        assert_eq!(state.compute_state_hash(), base_hash);
        assert_eq!(state.find_liquidity_asset_by_vault_outpoint(base_pool.vault_outpoint).unwrap(), Some(asset_id));
        assert_eq!(state.find_liquidity_asset_by_vault_outpoint(branch_a_pool.vault_outpoint).unwrap(), None);

        let (buy_b_tx, buy_b_auth_inputs) = build_buy(&base_pool, 7_120, 11 * MIN_LIQUIDITY_SEED_RESERVE_SOMPI);
        let block_b = BlockHash::from_u64_word(7_130);
        apply_block(&mut state, block_b, vec![tx_ref(buy_b_tx.clone(), BlockHash::from_u64_word(7_129), 0, 0)], &buy_b_auth_inputs);

        let mut fresh_branch_b = base_state;
        apply_block(&mut fresh_branch_b, block_b, vec![tx_ref(buy_b_tx, BlockHash::from_u64_word(7_129), 0, 0)], &buy_b_auth_inputs);
        assert_eq!(state.compute_state_hash(), fresh_branch_b.compute_state_hash());
        assert_eq!(state.get_token_nonce(owner, asset_id), 2);
    }

    #[test]
    fn liquidity_buy_rejects_noncanonical_integer_overpay() {
        let mut state = AtomicTokenState::new(1, "cryptix-simnet".to_string());
        let owner_payload = vec![0x21; 32];
        let owner = state.owner_id_from_address_components(0, owner_payload.as_slice()).expect("owner id should derive");
        let asset_id = [0x21; 32];
        let vault_outpoint = TransactionOutpoint::new(BlockHash::from_u64_word(21), 0);
        let overpay_in_sompi = 10 * MIN_LIQUIDITY_SEED_RESERVE_SOMPI;

        state.assets.insert(
            asset_id,
            TokenAsset {
                asset_id,
                creator_owner_id: owner,
                asset_class: TokenAssetClass::Liquidity,
                token_version: CURRENT_TOKEN_VERSION,
                mint_authority_owner_id: [0u8; 32],
                decimals: 0,
                supply_mode: SupplyMode::Capped,
                max_supply: crate::liquidity_math::LIQUIDITY_TOKEN_SUPPLY_RAW,
                total_supply: 0,
                name: b"Overpay".to_vec(),
                symbol: b"OVR".to_vec(),
                metadata: vec![],
                platform_tag: Vec::new(),
                created_block_hash: None,
                created_daa_score: None,
                created_at: None,
                liquidity: Some(LiquidityPoolState {
                    pool_nonce: 1,
                    curve_version: CURRENT_LIQUIDITY_CURVE_VERSION,
                    curve_mode: DEFAULT_LIQUIDITY_CURVE_MODE,
                    individual_virtual_cpay_reserves_sompi: 0,
                    individual_virtual_token_multiplier_bps: 0,
                    real_cpay_reserves_sompi: MIN_LIQUIDITY_SEED_RESERVE_SOMPI,
                    real_token_reserves: crate::liquidity_math::LIQUIDITY_TOKEN_SUPPLY_RAW,
                    virtual_cpay_reserves_sompi: INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI,
                    virtual_token_reserves: crate::liquidity_math::INITIAL_VIRTUAL_TOKEN_RESERVES,
                    unclaimed_fee_total_sompi: 0,
                    fee_bps: 0,
                    fee_recipients: vec![],
                    vault_outpoint,
                    vault_value_sompi: MIN_LIQUIDITY_SEED_RESERVE_SOMPI,
                    unlock_target_sompi: 0,
                    unlocked: true,
                    holder_addresses: HashMap::new(),
                }),
            },
        );

        let buy_tx = tx_with_inputs_outputs(
            vec![(vault_outpoint, 0)],
            vec![TransactionOutput::new(MIN_LIQUIDITY_SEED_RESERVE_SOMPI + overpay_in_sompi, liquidity_vault_script())],
            vec![],
        );
        let mut buy_auth_inputs = HashMap::new();
        buy_auth_inputs.insert(vault_outpoint, UtxoEntry::new(MIN_LIQUIDITY_SEED_RESERVE_SOMPI, liquidity_vault_script(), 0, false));
        let buyer_auth = AuthContext { owner_id: owner, address_version: 0, address_payload: owner_payload };
        let buy_op = BuyLiquidityExactInOp { asset_id, expected_pool_nonce: 1, cpay_in_sompi: overpay_in_sompi, min_token_out: 1 };
        let mut journal = JournalBuilder::default();

        assert_eq!(
            state.execute_buy_liquidity(&buy_tx, &buyer_auth, &buy_op, &buy_auth_inputs, &mut journal),
            Err(NoopReason::InvalidAmount)
        );
    }

    #[test]
    fn rejected_liquidity_buy_does_not_partially_mint_balance() {
        let mut state = AtomicTokenState::new(1, "cryptix-simnet".to_string());
        let owner_payload = vec![0x2A; 32];
        let owner = state.owner_id_from_address_components(0, owner_payload.as_slice()).expect("owner id should derive");
        let asset_id = [0x2A; 32];
        let vault_outpoint = TransactionOutpoint::new(BlockHash::from_u64_word(42), 0);
        let real_token_reserves = 1_000_000u128;
        let virtual_cpay_reserves = 1_000_000u64;
        let virtual_token_reserves = 1_000_000u128;
        let quote_gross_in = 10_000u64;
        let token_out = cpmm_buy(real_token_reserves, virtual_cpay_reserves, virtual_token_reserves, quote_gross_in)
            .expect("buy quote should calculate")
            .0;
        assert!(token_out > 0, "test setup expected non-zero token_out");
        let canonical_in = crate::liquidity_math::min_gross_input_for_token_out(
            real_token_reserves,
            virtual_cpay_reserves,
            virtual_token_reserves,
            token_out,
            0,
        )
        .expect("canonical input should calculate");

        state.assets.insert(
            asset_id,
            TokenAsset {
                asset_id,
                creator_owner_id: owner,
                asset_class: TokenAssetClass::Liquidity,
                token_version: CURRENT_TOKEN_VERSION,
                mint_authority_owner_id: [0u8; 32],
                decimals: 0,
                supply_mode: SupplyMode::Capped,
                max_supply: u128::MAX,
                total_supply: u128::MAX,
                name: b"Overflow".to_vec(),
                symbol: b"OVF".to_vec(),
                metadata: vec![],
                platform_tag: Vec::new(),
                created_block_hash: None,
                created_daa_score: None,
                created_at: None,
                liquidity: Some(LiquidityPoolState {
                    pool_nonce: 1,
                    curve_version: CURRENT_LIQUIDITY_CURVE_VERSION,
                    curve_mode: DEFAULT_LIQUIDITY_CURVE_MODE,
                    individual_virtual_cpay_reserves_sompi: 0,
                    individual_virtual_token_multiplier_bps: 0,
                    real_cpay_reserves_sompi: 1_000,
                    real_token_reserves,
                    virtual_cpay_reserves_sompi: virtual_cpay_reserves,
                    virtual_token_reserves,
                    unclaimed_fee_total_sompi: 0,
                    fee_bps: 0,
                    fee_recipients: vec![],
                    vault_outpoint,
                    vault_value_sompi: 1_000,
                    unlock_target_sompi: 0,
                    unlocked: true,
                    holder_addresses: HashMap::new(),
                }),
            },
        );
        state.rebuild_liquidity_vault_outpoint_index();

        let buy_tx = tx_with_inputs_outputs(
            vec![(vault_outpoint, 0)],
            vec![TransactionOutput::new(1_000 + canonical_in, liquidity_vault_script())],
            vec![],
        );
        let mut buy_auth_inputs = HashMap::new();
        buy_auth_inputs.insert(vault_outpoint, UtxoEntry::new(1_000, liquidity_vault_script(), 0, false));
        let buyer_auth = AuthContext { owner_id: owner, address_version: 0, address_payload: owner_payload };
        let buy_op = BuyLiquidityExactInOp { asset_id, expected_pool_nonce: 1, cpay_in_sompi: canonical_in, min_token_out: 1 };
        let mut journal = JournalBuilder::default();

        assert_eq!(
            state.execute_buy_liquidity(&buy_tx, &buyer_auth, &buy_op, &buy_auth_inputs, &mut journal),
            Err(NoopReason::SupplyOverflow)
        );
        assert_eq!(state.get_balance(asset_id, owner), 0, "rejected buy must not mint balance");
        let pool = state.assets.get(&asset_id).and_then(|asset| asset.liquidity.as_ref()).expect("pool should still exist");
        assert_eq!(pool.pool_nonce, 1);
        assert_eq!(pool.vault_outpoint, vault_outpoint);
        assert_eq!(pool.vault_value_sompi, 1_000);
    }

    #[test]
    fn rejected_create_asset_with_mint_does_not_leave_partial_asset() {
        let mut state = AtomicTokenState::new(1, "cryptix-simnet".to_string());
        let asset_id = [0x3A; 32];
        let creator = [0x3B; 32];
        let receiver = [0x3C; 32];
        let op = CreateAssetWithMintOp {
            token_version: CURRENT_TOKEN_VERSION,
            decimals: 8,
            supply_mode: SupplyMode::Capped,
            max_supply: 100,
            mint_authority_owner_id: creator,
            name: b"Cap".to_vec(),
            symbol: b"CAP".to_vec(),
            metadata: vec![],
            platform_tag: Vec::new(),
            initial_mint_amount: 101,
            initial_mint_to_owner_id: receiver,
        };
        let mut journal = JournalBuilder::default();

        assert_eq!(
            state.execute_create_asset_with_mint(asset_id, creator, &op, BlockHash::from_u64_word(1), 1, 1, &mut journal),
            Err(NoopReason::SupplyCapExceeded)
        );
        assert!(state.asset_value(&asset_id).is_none(), "rejected create-mint must not create an asset");
        assert_eq!(state.get_balance(asset_id, receiver), 0, "rejected create-mint must not mint balance");
    }

    #[test]
    fn liquidity_lock_blocks_outflows_until_buy_reaches_target_then_stays_unlocked() {
        let mut state = AtomicTokenState::new(1, "cryptix-simnet".to_string());
        let owner_script = test_script(33);
        let owner_payload = vec![0x33; 32];
        let owner = state.owner_id_from_address_components(0, owner_payload.as_slice()).expect("owner id should derive");
        let asset_id = [0x44; 32];
        let vault_outpoint = TransactionOutpoint::new(BlockHash::from_u64_word(44), 0);
        let buy_budget_sompi = 10 * MIN_LIQUIDITY_SEED_RESERVE_SOMPI;
        let budget_token_out = cpmm_buy(
            1_000,
            INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI,
            crate::liquidity_math::INITIAL_VIRTUAL_TOKEN_RESERVES,
            buy_budget_sompi,
        )
        .expect("buy quote should work")
        .0;
        let buy_in_sompi = crate::liquidity_math::min_gross_input_for_token_out(
            1_000,
            INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI,
            crate::liquidity_math::INITIAL_VIRTUAL_TOKEN_RESERVES,
            budget_token_out,
            0,
        )
        .expect("canonical buy should calculate");
        let target = MIN_LIQUIDITY_SEED_RESERVE_SOMPI + buy_in_sompi;

        state.assets.insert(
            asset_id,
            TokenAsset {
                asset_id,
                creator_owner_id: owner,
                asset_class: TokenAssetClass::Liquidity,
                token_version: CURRENT_TOKEN_VERSION,
                mint_authority_owner_id: [0u8; 32],
                decimals: 0,
                supply_mode: SupplyMode::Capped,
                max_supply: 1_000,
                total_supply: 0,
                name: b"Lock".to_vec(),
                symbol: b"LCK".to_vec(),
                metadata: vec![],
                platform_tag: Vec::new(),
                created_block_hash: None,
                created_daa_score: None,
                created_at: None,
                liquidity: Some(LiquidityPoolState {
                    pool_nonce: 1,
                    curve_version: CURRENT_LIQUIDITY_CURVE_VERSION,
                    curve_mode: DEFAULT_LIQUIDITY_CURVE_MODE,
                    individual_virtual_cpay_reserves_sompi: 0,
                    individual_virtual_token_multiplier_bps: 0,
                    real_cpay_reserves_sompi: MIN_LIQUIDITY_SEED_RESERVE_SOMPI,
                    real_token_reserves: 1_000,
                    virtual_cpay_reserves_sompi: INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI,
                    virtual_token_reserves: crate::liquidity_math::INITIAL_VIRTUAL_TOKEN_RESERVES,
                    unclaimed_fee_total_sompi: 0,
                    fee_bps: 0,
                    fee_recipients: vec![],
                    vault_outpoint,
                    vault_value_sompi: MIN_LIQUIDITY_SEED_RESERVE_SOMPI,
                    unlock_target_sompi: target,
                    unlocked: false,
                    holder_addresses: HashMap::new(),
                }),
            },
        );

        let dummy_tx = tx_with_inputs_outputs(vec![], vec![], vec![]);
        let mut journal = JournalBuilder::default();
        let locked_sell = SellLiquidityExactInOp {
            asset_id,
            expected_pool_nonce: 1,
            token_in: 1,
            min_cpay_out_sompi: 1,
            cpay_receive_output_index: 1,
        };
        assert_eq!(
            state.execute_sell_liquidity(&dummy_tx, owner, &locked_sell, &HashMap::new(), &mut journal),
            Err(NoopReason::LiquiditySellLocked)
        );
        let locked_claim = ClaimLiquidityFeesOp {
            asset_id,
            expected_pool_nonce: 1,
            recipient_index: 0,
            claim_amount_sompi: 1,
            claim_receive_output_index: 1,
        };
        assert_eq!(
            state.execute_claim_liquidity_fees(&dummy_tx, owner, &locked_claim, &HashMap::new(), &mut journal),
            Err(NoopReason::LiquiditySellLocked)
        );

        let buy_tx =
            tx_with_inputs_outputs(vec![(vault_outpoint, 0)], vec![TransactionOutput::new(target, liquidity_vault_script())], vec![]);
        let mut buy_auth_inputs = HashMap::new();
        buy_auth_inputs.insert(vault_outpoint, UtxoEntry::new(MIN_LIQUIDITY_SEED_RESERVE_SOMPI, liquidity_vault_script(), 0, false));
        let buyer_auth = AuthContext { owner_id: owner, address_version: 0, address_payload: owner_payload };
        let buy_op = BuyLiquidityExactInOp { asset_id, expected_pool_nonce: 1, cpay_in_sompi: buy_in_sompi, min_token_out: 1 };
        let token_out = state
            .execute_buy_liquidity(&buy_tx, &buyer_auth, &buy_op, &buy_auth_inputs, &mut journal)
            .expect("buy should unlock the pool");
        assert!(token_out > 1);

        let pool_after_buy = state.assets.get(&asset_id).and_then(|asset| asset.liquidity.as_ref()).expect("pool should exist");
        assert!(pool_after_buy.unlocked);
        assert_eq!(pool_after_buy.unlock_target_sompi, target);
        assert_eq!(pool_after_buy.real_cpay_reserves_sompi, target);

        let (cpay_out, new_real_cpay_reserves_sompi, _, _) = cpmm_sell(
            pool_after_buy.real_cpay_reserves_sompi,
            pool_after_buy.virtual_cpay_reserves_sompi,
            pool_after_buy.virtual_token_reserves,
            1,
        )
        .expect("sell quote should work");
        assert!(new_real_cpay_reserves_sompi < target);
        let sell_tx = tx_with_inputs_outputs(
            vec![(pool_after_buy.vault_outpoint, 0)],
            vec![
                TransactionOutput::new(pool_after_buy.vault_value_sompi - cpay_out, liquidity_vault_script()),
                TransactionOutput::new(cpay_out, owner_script),
            ],
            vec![],
        );
        let mut sell_auth_inputs = HashMap::new();
        sell_auth_inputs.insert(
            pool_after_buy.vault_outpoint,
            UtxoEntry::new(pool_after_buy.vault_value_sompi, liquidity_vault_script(), 0, false),
        );
        let sell_op = SellLiquidityExactInOp {
            asset_id,
            expected_pool_nonce: pool_after_buy.pool_nonce,
            token_in: 1,
            min_cpay_out_sompi: 1,
            cpay_receive_output_index: 1,
        };
        state
            .execute_sell_liquidity(&sell_tx, owner, &sell_op, &sell_auth_inputs, &mut journal)
            .expect("sell should be allowed after unlock");

        let pool_after_sell = state.assets.get(&asset_id).and_then(|asset| asset.liquidity.as_ref()).expect("pool should exist");
        assert!(pool_after_sell.unlocked);
        assert!(pool_after_sell.real_cpay_reserves_sompi < target);
    }

    #[test]
    fn liquidity_invariants_reject_mismatched_holder_owner_id() {
        let state = AtomicTokenState::new(1, "cryptix-simnet".to_string());
        let asset_id = [0xAA; 32];
        let creator_owner = [0xBB; 32];
        let wrong_owner = [0xCC; 32];

        let mut holder_addresses = HashMap::new();
        holder_addresses.insert(wrong_owner, LiquidityHolderAddressState { address_version: 0, address_payload: vec![0x99; 32] });

        let asset = TokenAsset {
            asset_id,
            creator_owner_id: creator_owner,
            asset_class: TokenAssetClass::Liquidity,
            token_version: CURRENT_TOKEN_VERSION,
            mint_authority_owner_id: [0u8; 32],
            decimals: 8,
            supply_mode: SupplyMode::Capped,
            max_supply: 500,
            total_supply: 100,
            name: b"LiqX".to_vec(),
            symbol: b"LX".to_vec(),
            metadata: vec![],
            platform_tag: Vec::new(),
            created_block_hash: None,
            created_daa_score: None,
            created_at: None,
            liquidity: Some(LiquidityPoolState {
                pool_nonce: 1,
                curve_version: CURRENT_LIQUIDITY_CURVE_VERSION,
                curve_mode: DEFAULT_LIQUIDITY_CURVE_MODE,
                individual_virtual_cpay_reserves_sompi: 0,
                individual_virtual_token_multiplier_bps: 0,
                real_cpay_reserves_sompi: 50_000,
                real_token_reserves: 400,
                virtual_cpay_reserves_sompi: INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI,
                virtual_token_reserves: crate::liquidity_math::INITIAL_VIRTUAL_TOKEN_RESERVES,
                unclaimed_fee_total_sompi: 0,
                fee_bps: 0,
                fee_recipients: vec![],
                vault_outpoint: TransactionOutpoint::new(BlockHash::from_u64_word(8), 0),
                vault_value_sompi: 50_000,
                unlock_target_sompi: 0,
                unlocked: true,
                holder_addresses,
            }),
        };

        let err = state.validate_liquidity_invariants(&asset).expect_err("invariants should fail");
        assert_eq!(err, NoopReason::InternalMalformedAcceptance);
    }

    #[test]
    fn liquidity_invariants_reject_real_cpay_below_floor() {
        let state = AtomicTokenState::new(1, "cryptix-simnet".to_string());
        let asset = TokenAsset {
            asset_id: [0xAB; 32],
            creator_owner_id: [0xBC; 32],
            asset_class: TokenAssetClass::Liquidity,
            token_version: CURRENT_TOKEN_VERSION,
            mint_authority_owner_id: [0u8; 32],
            decimals: 8,
            supply_mode: SupplyMode::Capped,
            max_supply: 500,
            total_supply: 1,
            name: b"LiqY".to_vec(),
            symbol: b"LY".to_vec(),
            metadata: vec![],
            platform_tag: Vec::new(),
            created_block_hash: None,
            created_daa_score: None,
            created_at: None,
            liquidity: Some(LiquidityPoolState {
                pool_nonce: 1,
                curve_version: CURRENT_LIQUIDITY_CURVE_VERSION,
                curve_mode: DEFAULT_LIQUIDITY_CURVE_MODE,
                individual_virtual_cpay_reserves_sompi: 0,
                individual_virtual_token_multiplier_bps: 0,
                real_cpay_reserves_sompi: 0,
                real_token_reserves: 499,
                virtual_cpay_reserves_sompi: INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI,
                virtual_token_reserves: crate::liquidity_math::INITIAL_VIRTUAL_TOKEN_RESERVES,
                unclaimed_fee_total_sompi: 0,
                fee_bps: 0,
                fee_recipients: vec![],
                vault_outpoint: TransactionOutpoint::new(BlockHash::from_u64_word(9), 0),
                vault_value_sompi: 0,
                unlock_target_sompi: 0,
                unlocked: true,
                holder_addresses: HashMap::new(),
            }),
        };

        let err = state.validate_liquidity_invariants(&asset).expect_err("invariants should fail");
        assert_eq!(err, NoopReason::InternalMalformedAcceptance);
    }

    #[test]
    fn liquidity_claim_authorization_requires_matching_owner() {
        assert!(validate_liquidity_claim_authorization([0x10; 32], [0x10; 32]).is_ok());
        assert_eq!(validate_liquidity_claim_authorization([0x10; 32], [0x20; 32]), Err(NoopReason::BadAuthInput));
    }

    #[test]
    fn liquidity_transfer_is_allowed_for_liquidity_assets() {
        let mut state = AtomicTokenState::new(1, "cryptix-simnet".to_string());
        let asset_id = [0xD1; 32];
        let sender_address_payload = vec![0x77; 32];
        let sender_owner =
            state.owner_id_from_address_components(0, sender_address_payload.as_slice()).expect("sender owner id should derive");
        let recipient_owner = [0xD3; 32];
        let mut holder_addresses = HashMap::new();
        holder_addresses
            .insert(sender_owner, LiquidityHolderAddressState { address_version: 0, address_payload: sender_address_payload });

        state.assets.insert(
            asset_id,
            TokenAsset {
                asset_id,
                creator_owner_id: sender_owner,
                asset_class: TokenAssetClass::Liquidity,
                token_version: CURRENT_TOKEN_VERSION,
                mint_authority_owner_id: [0u8; 32],
                decimals: 8,
                supply_mode: SupplyMode::Capped,
                max_supply: 1_000,
                total_supply: 100,
                name: b"Liquidity".to_vec(),
                symbol: b"LIQ".to_vec(),
                metadata: vec![],
                platform_tag: Vec::new(),
                created_block_hash: None,
                created_daa_score: None,
                created_at: None,
                liquidity: Some(LiquidityPoolState {
                    pool_nonce: 1,
                    curve_version: CURRENT_LIQUIDITY_CURVE_VERSION,
                    curve_mode: DEFAULT_LIQUIDITY_CURVE_MODE,
                    individual_virtual_cpay_reserves_sompi: 0,
                    individual_virtual_token_multiplier_bps: 0,
                    real_cpay_reserves_sompi: 50_000,
                    real_token_reserves: 900,
                    virtual_cpay_reserves_sompi: INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI,
                    virtual_token_reserves: crate::liquidity_math::INITIAL_VIRTUAL_TOKEN_RESERVES,
                    unclaimed_fee_total_sompi: 0,
                    fee_bps: 0,
                    fee_recipients: vec![],
                    vault_outpoint: TransactionOutpoint::new(BlockHash::from_u64_word(10), 0),
                    vault_value_sompi: 50_000,
                    unlock_target_sompi: 0,
                    unlocked: true,
                    holder_addresses,
                }),
            },
        );
        state.balances.insert(BalanceKey { asset_id, owner_id: sender_owner }, 100);

        let mut journal = JournalBuilder::default();
        state.execute_transfer(sender_owner, asset_id, recipient_owner, 25, &mut journal).expect("liquidity transfer should succeed");

        assert_eq!(state.balances.get(&BalanceKey { asset_id, owner_id: sender_owner }), Some(&75));
        assert_eq!(state.balances.get(&BalanceKey { asset_id, owner_id: recipient_owner }), Some(&25));
    }

    #[test]
    fn state_hash_ignores_prunable_processed_ops() {
        let mut state = AtomicTokenState::new(1, "cryptix-simnet".to_string());
        let before = state.compute_state_hash();
        state.processed_ops.insert(
            BlockHash::from_u64_word(99),
            ProcessedOp {
                accepting_block_hash: BlockHash::from_u64_word(100),
                apply_status: ApplyStatus::Applied,
                noop_reason: NoopReason::None,
            },
        );
        let after = state.compute_state_hash();
        assert_eq!(before, after);
    }

    #[test]
    fn state_hash_ignores_events() {
        let mut state = AtomicTokenState::new(1, "cryptix-simnet".to_string());
        let before = state.compute_state_hash();
        state.events.push(TokenEvent {
            event_id: [0xAA; 32],
            sequence: 1,
            accepting_block_hash: BlockHash::from_u64_word(10),
            txid: BlockHash::from_u64_word(11),
            event_type: EventType::Applied,
            apply_status: ApplyStatus::Applied,
            noop_reason: NoopReason::None,
            ordinal: 0,
            reorg_of_event_id: None,
            details: TokenEventDetails::default(),
        });
        let after = state.compute_state_hash();
        assert_eq!(before, after);
    }

    #[test]
    fn prune_history_discards_prunable_processed_ops_and_events() {
        let mut state = AtomicTokenState::new(1, "cryptix-simnet".to_string());
        for index in 1..=4u64 {
            let block_hash = BlockHash::from_u64_word(index);
            state.applied_chain_order.push(block_hash);
            state.block_journals.insert(block_hash, BlockJournal::default());
            state.state_hash_by_block.insert(block_hash, [index as u8; 32]);
            state.event_sequence_by_block.insert(block_hash, index);
            state.processed_ops.insert(
                BlockHash::from_u64_word(1000 + index),
                ProcessedOp { accepting_block_hash: block_hash, apply_status: ApplyStatus::Applied, noop_reason: NoopReason::None },
            );
            state.events.push(TokenEvent {
                event_id: [index as u8; 32],
                sequence: index,
                accepting_block_hash: block_hash,
                txid: BlockHash::from_u64_word(2000 + index),
                event_type: EventType::Applied,
                apply_status: ApplyStatus::Applied,
                noop_reason: NoopReason::None,
                ordinal: 0,
                reorg_of_event_id: None,
                details: TokenEventDetails::default(),
            });
        }
        state.next_event_sequence = 4;
        state.rebuild_event_id_index();

        state.prune_history(2);

        assert_eq!(state.applied_chain_order, vec![BlockHash::from_u64_word(3), BlockHash::from_u64_word(4)]);
        assert_eq!(state.processed_ops.len(), 2);
        assert!(state.processed_ops.values().all(
            |op| matches!(op.accepting_block_hash, hash if hash == BlockHash::from_u64_word(3) || hash == BlockHash::from_u64_word(4))
        ));
        assert_eq!(state.events.iter().map(|event| event.sequence).collect::<Vec<_>>(), vec![3, 4]);
        assert_eq!(state.event_ids.len(), 2);
        assert_eq!(state.next_event_sequence, 4);
    }

    #[test]
    fn prune_history_keeps_committed_checkpoint_hashes_stable_when_processed_ops_are_pruned() {
        let mut state = AtomicTokenState::new(1, "cryptix-simnet".to_string());
        for index in 1..=4u64 {
            let block_hash = BlockHash::from_u64_word(index);
            let txid = BlockHash::from_u64_word(1000 + index);
            state.processed_ops.insert(
                txid,
                ProcessedOp { accepting_block_hash: block_hash, apply_status: ApplyStatus::Applied, noop_reason: NoopReason::None },
            );
            state.block_journals.insert(block_hash, BlockJournal { added_processed_ops: vec![txid], ..Default::default() });
            state.applied_chain_order.push(block_hash);
            state.state_hash_by_block.insert(block_hash, state.compute_state_hash());
            state.event_sequence_by_block.insert(block_hash, index);
        }
        let tip = BlockHash::from_u64_word(4);
        let stale_tip_hash = state.get_state_hash_at_block(tip).expect("tip hash should exist");

        assert!(state.prune_history(2));
        assert_eq!(state.applied_chain_order, vec![BlockHash::from_u64_word(3), tip]);
        assert_eq!(state.compute_state_hash(), stale_tip_hash);
        assert_eq!(state.get_state_hash_at_block(tip), Some(stale_tip_hash));

        let refreshed = state.refresh_retained_state_hashes_from_current_state().expect("refresh should succeed");
        assert_eq!(refreshed, 2);
        assert_eq!(state.get_state_hash_at_block(tip), Some(stale_tip_hash));
    }

    #[test]
    fn point_reads_rollback_only_requested_atomic_keys() {
        let mut state = AtomicTokenState::new(1, "cryptix-simnet".to_string());
        let asset_id = [0xA1; 32];
        let owner = [0xB2; 32];
        let receiver = [0xC3; 32];
        let block1 = BlockHash::from_u64_word(91);
        let block2 = BlockHash::from_u64_word(92);
        let asset = TokenAsset {
            asset_id,
            creator_owner_id: owner,
            asset_class: TokenAssetClass::Standard,
            token_version: CURRENT_TOKEN_VERSION,
            mint_authority_owner_id: owner,
            decimals: 0,
            supply_mode: SupplyMode::Capped,
            max_supply: 10,
            total_supply: 10,
            name: b"Point".to_vec(),
            symbol: b"PNT".to_vec(),
            metadata: Vec::new(),
            platform_tag: Vec::new(),
            created_block_hash: Some(block1),
            created_daa_score: Some(1),
            created_at: Some(1),
            liquidity: None,
        };
        let owner_balance = BalanceKey { asset_id, owner_id: owner };
        let receiver_balance = BalanceKey { asset_id, owner_id: receiver };
        let nonce_key = NonceKey::asset(owner, asset_id);

        state.assets.insert(asset_id, asset.clone());
        state.balances.insert(owner_balance, 10);
        state.nonces.insert(nonce_key, 2);
        state.applied_chain_order.push(block1);
        state.block_journals.insert(
            block1,
            BlockJournal {
                changed_assets: vec![ChangedAsset { asset_id, old_value: None }],
                changed_balances: vec![ChangedBalance { key: owner_balance, old_value: None }],
                changed_nonces: vec![ChangedNonce { key: nonce_key, old_value: None }],
                ..Default::default()
            },
        );
        state.state_hash_by_block.insert(block1, state.compute_state_hash());
        state.event_sequence_by_block.insert(block1, 1);

        state.balances.insert(owner_balance, 4);
        state.balances.insert(receiver_balance, 6);
        state.nonces.insert(nonce_key, 3);
        state.applied_chain_order.push(block2);
        state.block_journals.insert(
            block2,
            BlockJournal {
                changed_balances: vec![
                    ChangedBalance { key: owner_balance, old_value: Some(10) },
                    ChangedBalance { key: receiver_balance, old_value: None },
                ],
                changed_nonces: vec![ChangedNonce { key: nonce_key, old_value: Some(2) }],
                ..Default::default()
            },
        );
        state.state_hash_by_block.insert(block2, state.compute_state_hash());
        state.event_sequence_by_block.insert(block2, 2);

        assert_eq!(state.get_balance_at_block(owner_balance, block1), Some(10));
        assert_eq!(state.get_balance_at_block(receiver_balance, block1), Some(0));
        assert_eq!(state.get_nonce_at_block(nonce_key, block1), Some(2));
        assert_eq!(state.get_asset_at_block(asset_id, block1), Some(Some(asset)));
        assert_eq!(state.indexed_balances_by_owner_at_block(owner, false, block1), Some(vec![(asset_id, 10, None)]));
        assert_eq!(state.indexed_holders_by_asset_at_block(asset_id, block1), Some(vec![(owner, 10)]));
    }

    #[test]
    fn first_replayable_block_hash_uses_contiguous_journal_suffix() {
        let mut state = AtomicTokenState::new(1, "cryptix-simnet".to_string());
        let blocks = (1..=5u64).map(BlockHash::from_u64_word).collect::<Vec<_>>();
        state.applied_chain_order = blocks.clone();
        state.block_journals.insert(blocks[2], BlockJournal::default());
        state.block_journals.insert(blocks[3], BlockJournal::default());
        state.block_journals.insert(blocks[4], BlockJournal::default());

        assert_eq!(state.first_replayable_block_hash(), Some(blocks[2]));

        state.block_journals.remove(&blocks[4]);
        assert_eq!(state.first_replayable_block_hash(), None);
    }

    #[test]
    fn export_snapshot_state_chain_is_replay_window_suffix() {
        let mut state = AtomicTokenState::new(1, "cryptix-simnet".to_string());
        let auth_inputs = HashMap::new();
        let block1 = BlockHash::from_u64_word(7001);
        let block2 = BlockHash::from_u64_word(7002);
        let block3 = BlockHash::from_u64_word(7003);

        apply_block(&mut state, block1, vec![], &auth_inputs);
        let window_start_parent_hash = state.get_state_hash_at_block(block1);
        apply_block(&mut state, block2, vec![], &auth_inputs);
        apply_block(&mut state, block3, vec![], &auth_inputs);

        let snapshot = state.export_snapshot(block3, 77, block1, &[block2, block3]).expect("snapshot export must succeed");

        assert_eq!(snapshot.state.applied_chain_order, vec![block2, block3]);
        assert_eq!(snapshot.state.state_hash_by_block.len(), 2);
        assert!(snapshot.state.state_hash_by_block.contains_key(&block2));
        assert!(snapshot.state.state_hash_by_block.contains_key(&block3));
        assert_eq!(snapshot.state_hash_at_window_start_parent, window_start_parent_hash);
    }

    #[test]
    fn export_snapshot_parent_hash_uses_materialized_state_not_stale_cache() {
        let mut state = AtomicTokenState::new(1, "cryptix-simnet".to_string());
        let auth_inputs = HashMap::new();
        let block1 = BlockHash::from_u64_word(7101);
        let block2 = BlockHash::from_u64_word(7102);
        let block3 = BlockHash::from_u64_word(7103);

        apply_block(&mut state, block1, vec![], &auth_inputs);
        let expected_parent_hash = state.materialize_view_at_block(block1).expect("parent view should materialize").state_hash;
        let stale_parent_hash = [9u8; 32];
        state.state_hash_by_block.insert(block1, stale_parent_hash);
        apply_block(&mut state, block2, vec![], &auth_inputs);
        apply_block(&mut state, block3, vec![], &auth_inputs);

        let snapshot = state.export_snapshot(block3, 77, block1, &[block2, block3]).expect("snapshot export must succeed");

        assert_eq!(snapshot.state_hash_at_window_start_parent, Some(expected_parent_hash));
        assert_ne!(snapshot.state_hash_at_window_start_parent, Some(stale_parent_hash));
    }

    #[test]
    fn snapshot_import_preserves_processed_ops_for_duplicate_replay_guard() {
        let network = "cryptix-simnet".to_string();
        let mut state = AtomicTokenState::new(1, network.clone());
        let owner_script = test_script(93);
        let owner = owner_id(&state, &owner_script);
        let outpoint = TransactionOutpoint::new(BlockHash::from_u64_word(8100), 0);
        let mut auth_inputs = HashMap::new();
        auth_inputs.insert(outpoint, UtxoEntry::new(1000, owner_script.clone(), 0, false));

        let create_tx = token_tx(outpoint, owner_script, payload_create_asset(0, 1, 8, owner, b"Dup", b"DUP", b""));
        let duplicate_txid = create_tx.id();
        let block1 = BlockHash::from_u64_word(8101);
        let block2 = BlockHash::from_u64_word(8102);
        let refs_block1 = vec![tx_ref(create_tx.clone(), block1, 0, 0)];
        let refs_block2 = vec![tx_ref(create_tx.clone(), block2, 0, 0)];

        apply_block(&mut state, block1, refs_block1, &auth_inputs);
        apply_block(&mut state, block2, refs_block2.clone(), &auth_inputs);
        let expected_hash = state.compute_state_hash();
        let snapshot = state.export_snapshot(block2, 99, block1, &[block2]).expect("snapshot export must succeed");

        assert_eq!(snapshot.state.applied_chain_order, vec![block2]);
        assert!(snapshot.state.processed_ops.contains_key(&duplicate_txid));
        assert!(snapshot.journals_in_window[0].1.added_processed_ops.is_empty());

        let mut recovered = AtomicTokenState::new(1, network);
        recovered.import_snapshot(snapshot.clone()).expect("snapshot import should succeed");
        recovered.rollback_snapshot_window_to_parent(snapshot.window_start_block_hash).expect("snapshot rollback should succeed");
        apply_block(&mut recovered, block2, refs_block2, &auth_inputs);

        assert_eq!(recovered.compute_state_hash(), expected_hash);
    }

    #[test]
    fn duplicate_processed_cat_replay_does_not_apply_anchor_deltas_again() {
        let mut state = AtomicTokenState::new(1, "cryptix-simnet".to_string());
        let owner_script = test_script(94);
        let receiver_script = test_script(95);
        let owner = owner_id(&state, &owner_script);
        let receiver = owner_id(&state, &receiver_script);
        let outpoint = TransactionOutpoint::new(BlockHash::from_u64_word(8200), 0);
        let mut auth_inputs = HashMap::new();
        auth_inputs.insert(outpoint, UtxoEntry::new(1000, owner_script.clone(), 0, false));

        let create_tx = tx_with_inputs_outputs(
            vec![(outpoint, 1)],
            vec![TransactionOutput::new(1, owner_script), TransactionOutput::new(1, receiver_script)],
            payload_create_asset(0, 1, 8, owner, b"DupAnchor", b"DPA", b""),
        );
        let duplicate_txid = create_tx.id();

        apply_block(
            &mut state,
            BlockHash::from_u64_word(8201),
            vec![tx_ref(create_tx.clone(), BlockHash::from_u64_word(9201), 0, 0)],
            &auth_inputs,
        );
        assert_eq!(state.get_anchor_count(receiver), 1);

        apply_block(
            &mut state,
            BlockHash::from_u64_word(8202),
            vec![tx_ref(create_tx, BlockHash::from_u64_word(9202), 0, 0)],
            &auth_inputs,
        );

        assert_eq!(state.get_anchor_count(receiver), 1, "duplicate CAT replay must not mutate anchor counts");
        assert_eq!(state.events.iter().filter(|event| event.txid == duplicate_txid).count(), 1);
        assert_eq!(state.processed_ops.get(&duplicate_txid).map(|op| op.accepting_block_hash), Some(BlockHash::from_u64_word(8201)));
    }

    #[test]
    fn persisted_processed_cat_guard_survives_v2_overlay_clear() {
        let dir = unique_temp_dir("persisted-processed-op-guard");
        let store = Arc::new(
            AtomicStorageV2::open(&dir, 1, "cryptix-simnet".to_string(), BlockHash::from_u64_word(1)).expect("open V2 store"),
        );
        let mut state = AtomicTokenState::new(1, "cryptix-simnet".to_string());
        state.attach_state_store(store.clone());

        let owner_script = test_script(104);
        let receiver_script = test_script(105);
        let owner = owner_id(&state, &owner_script);
        let receiver = owner_id(&state, &receiver_script);
        let outpoint = TransactionOutpoint::new(BlockHash::from_u64_word(9200), 0);
        let mut auth_inputs = HashMap::new();
        auth_inputs.insert(outpoint, UtxoEntry::new(1000, owner_script.clone(), 0, false));

        let create_tx = tx_with_inputs_outputs(
            vec![(outpoint, 1)],
            vec![TransactionOutput::new(1, owner_script), TransactionOutput::new(1, receiver_script)],
            payload_create_asset(0, 1, 8, owner, b"StoredDup", b"SDP", b""),
        );
        let txid = create_tx.id();
        let first_block = BlockHash::from_u64_word(9201);
        let duplicate_block = BlockHash::from_u64_word(9202);

        apply_block_and_commit(
            &mut state,
            first_block,
            vec![tx_ref(create_tx.clone(), BlockHash::from_u64_word(9301), 0, 0)],
            &auth_inputs,
        );
        assert!(state.processed_ops.is_empty(), "V2 commit should clear the in-memory processed-op overlay");
        assert_eq!(store.get_processed_op(&txid).expect("stored processed op").map(|op| op.accepting_block_hash), Some(first_block));
        assert_eq!(state.get_anchor_count(receiver), 1);

        apply_block_and_commit(
            &mut state,
            duplicate_block,
            vec![tx_ref(create_tx, BlockHash::from_u64_word(9302), 0, 0)],
            &auth_inputs,
        );

        assert_eq!(state.get_anchor_count(receiver), 1, "duplicate guard must be read from the V2 store after overlay clear");
        assert_eq!(state.events.iter().filter(|event| event.txid == txid).count(), 1);
        assert_eq!(store.get_processed_op(&txid).expect("stored processed op").map(|op| op.accepting_block_hash), Some(first_block));

        drop(state);
        drop(store);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn self_transfer_does_not_inflate_balance_or_supply() {
        let mut state = AtomicTokenState::new(1, "cryptix-simnet".to_string());
        let owner_script = test_script(88);
        let owner = owner_id(&state, &owner_script);

        let outpoint1 = TransactionOutpoint::new(BlockHash::from_u64_word(910), 0);
        let outpoint2 = TransactionOutpoint::new(BlockHash::from_u64_word(911), 0);
        let outpoint3 = TransactionOutpoint::new(BlockHash::from_u64_word(912), 0);
        let mut auth_inputs = HashMap::new();
        auth_inputs.insert(outpoint1, UtxoEntry::new(1000, owner_script.clone(), 0, false));
        auth_inputs.insert(outpoint2, UtxoEntry::new(1000, owner_script.clone(), 0, false));
        auth_inputs.insert(outpoint3, UtxoEntry::new(1000, owner_script.clone(), 0, false));

        let create_tx = token_tx(outpoint1, owner_script.clone(), payload_create_asset(0, 1, 8, owner, b"Self", b"SLF", b""));
        let asset_id = hash_bytes(create_tx.id());
        let mint_tx = token_tx(outpoint2, owner_script.clone(), payload_mint(0, 2, asset_id, owner, 1_000));
        let self_transfer_tx = token_tx(outpoint3, owner_script.clone(), payload_transfer(0, 3, asset_id, owner, 250));

        apply_block(
            &mut state,
            BlockHash::from_u64_word(1001),
            vec![tx_ref(create_tx, BlockHash::from_u64_word(2001), 0, 0), tx_ref(mint_tx, BlockHash::from_u64_word(2001), 1, 0)],
            &auth_inputs,
        );
        let before_balance = state.get_balance(asset_id, owner);
        let before_supply = state.get_asset(asset_id).expect("asset should exist").total_supply;

        apply_block(
            &mut state,
            BlockHash::from_u64_word(1002),
            vec![tx_ref(self_transfer_tx, BlockHash::from_u64_word(2002), 0, 0)],
            &auth_inputs,
        );

        let after_balance = state.get_balance(asset_id, owner);
        let after_supply = state.get_asset(asset_id).expect("asset should exist").total_supply;
        assert_eq!(after_balance, before_balance);
        assert_eq!(after_supply, before_supply);
    }

    #[test]
    fn event_and_asset_metadata_capture_explorer_fields() {
        let mut state = AtomicTokenState::new(1, "cryptix-simnet".to_string());
        let owner_script = test_script(51);
        let receiver_script = test_script(77);
        let owner = owner_id(&state, &owner_script);
        let receiver = owner_id(&state, &receiver_script);

        let outpoint1 = TransactionOutpoint::new(BlockHash::from_u64_word(1010), 0);
        let outpoint2 = TransactionOutpoint::new(BlockHash::from_u64_word(1011), 0);
        let outpoint3 = TransactionOutpoint::new(BlockHash::from_u64_word(1012), 0);

        let mut auth_inputs = HashMap::new();
        auth_inputs.insert(outpoint1, UtxoEntry::new(1000, owner_script.clone(), 0, false));
        auth_inputs.insert(outpoint2, UtxoEntry::new(1000, owner_script.clone(), 0, false));
        auth_inputs.insert(outpoint3, UtxoEntry::new(1000, owner_script.clone(), 0, false));

        let create_tx = token_tx(outpoint1, owner_script.clone(), payload_create_asset(0, 1, 8, owner, b"Meta", b"MTA", b""));
        let asset_id = hash_bytes(create_tx.id());
        let mint_tx = token_tx(outpoint2, owner_script.clone(), payload_mint(0, 2, asset_id, owner, 500));
        let transfer_tx = token_tx(outpoint3, owner_script.clone(), payload_transfer(0, 3, asset_id, receiver, 125));

        let mut journal = JournalBuilder::default();
        state.apply_transaction(
            BlockHash::from_u64_word(6001),
            123_456,
            1_715_123_000_000,
            &tx_ref_with_source_metadata(create_tx.clone(), BlockHash::from_u64_word(7001), 123_450, 1_715_122_999_000, 0, 0),
            0,
            &auth_inputs,
            &mut journal,
        );
        state.apply_transaction(
            BlockHash::from_u64_word(6002),
            123_457,
            1_715_123_000_500,
            &tx_ref(mint_tx.clone(), BlockHash::from_u64_word(7002), 0, 0),
            0,
            &auth_inputs,
            &mut journal,
        );
        state.apply_transaction(
            BlockHash::from_u64_word(6003),
            123_458,
            1_715_123_001_000,
            &tx_ref(transfer_tx.clone(), BlockHash::from_u64_word(7003), 0, 0),
            0,
            &auth_inputs,
            &mut journal,
        );

        let asset = state.get_asset(asset_id).expect("asset should exist");
        assert_eq!(asset.created_block_hash, Some(BlockHash::from_u64_word(7001)));
        assert_eq!(asset.created_daa_score, Some(123_450));
        assert_eq!(asset.created_at, Some(1_715_122_999_000));

        let transfer_event = state.events.iter().find(|event| event.txid == transfer_tx.id()).expect("transfer event should exist");
        assert_eq!(transfer_event.details.op_type, Some(TokenOpCode::Transfer));
        assert_eq!(transfer_event.details.asset_id, Some(asset_id));
        assert_eq!(transfer_event.details.from_owner_id, Some(owner));
        assert_eq!(transfer_event.details.to_owner_id, Some(receiver));
        assert_eq!(transfer_event.details.amount, Some(125));
    }

    #[test]
    fn import_snapshot_rejects_unbound_history_fields() {
        let network = "cryptix-simnet".to_string();
        let mut state = AtomicTokenState::new(1, network.clone());
        let owner_script = test_script(41);
        let owner = owner_id(&state, &owner_script);

        let outpoint1 = TransactionOutpoint::new(BlockHash::from_u64_word(920), 0);
        let outpoint2 = TransactionOutpoint::new(BlockHash::from_u64_word(921), 0);
        let mut auth_inputs = HashMap::new();
        auth_inputs.insert(outpoint1, UtxoEntry::new(1000, owner_script.clone(), 0, false));
        auth_inputs.insert(outpoint2, UtxoEntry::new(1000, owner_script.clone(), 0, false));

        let create_tx = token_tx(outpoint1, owner_script.clone(), payload_create_asset(0, 1, 8, owner, b"Snap", b"SNP", b""));
        let asset_id = hash_bytes(create_tx.id());
        let mint_tx = token_tx(outpoint2, owner_script.clone(), payload_mint(0, 2, asset_id, owner, 500));
        let block1 = BlockHash::from_u64_word(3001);
        let block2 = BlockHash::from_u64_word(3002);
        apply_block(&mut state, block1, vec![tx_ref(create_tx, BlockHash::from_u64_word(4001), 0, 0)], &auth_inputs);
        apply_block(&mut state, block2, vec![tx_ref(mint_tx, BlockHash::from_u64_word(4002), 0, 0)], &auth_inputs);

        let mut snapshot =
            state.export_snapshot(block2, 1234, BlockHash::from_u64_word(1), &[block1, block2]).expect("snapshot export must succeed");
        let expected_state_hash = snapshot.state_hash_at_fp;
        let expected_window_txids = snapshot
            .journals_in_window
            .iter()
            .flat_map(|(_, journal)| journal.added_processed_ops.iter().copied())
            .collect::<HashSet<_>>();
        let poisoned_txid = BlockHash::from_u64_word(0xDEAD_BEEF);

        snapshot.state.processed_ops.insert(
            poisoned_txid,
            ProcessedOp { accepting_block_hash: block2, apply_status: ApplyStatus::Applied, noop_reason: NoopReason::None },
        );
        snapshot.state.events.push(TokenEvent {
            event_id: [0xEE; 32],
            sequence: 1,
            accepting_block_hash: block2,
            txid: poisoned_txid,
            event_type: EventType::Applied,
            apply_status: ApplyStatus::Applied,
            noop_reason: NoopReason::None,
            ordinal: 999,
            reorg_of_event_id: None,
            details: TokenEventDetails::default(),
        });
        snapshot.state.next_event_sequence = u64::MAX;

        let mut recovered = AtomicTokenState::new(1, network);
        let err = recovered.import_snapshot(snapshot).expect_err("snapshot import must reject poisoned processed_ops");
        assert!(matches!(err, AtomicTokenError::Processing(message) if message.contains("outside the rollback window")));
        assert!(!expected_window_txids.contains(&poisoned_txid));
        assert_ne!(expected_state_hash, recovered.compute_state_hash());
    }

    #[test]
    fn import_snapshot_rejects_state_hash_index_outside_chain() {
        let network = "cryptix-simnet".to_string();
        let mut state = AtomicTokenState::new(1, network.clone());
        let owner_script = test_script(66);
        let owner = owner_id(&state, &owner_script);
        let outpoint = TransactionOutpoint::new(BlockHash::from_u64_word(930), 0);
        let mut auth_inputs = HashMap::new();
        auth_inputs.insert(outpoint, UtxoEntry::new(1000, owner_script.clone(), 0, false));
        let create_tx = token_tx(outpoint, owner_script, payload_create_asset(0, 1, 8, owner, b"Map", b"MAP", b""));
        let block = BlockHash::from_u64_word(5001);
        apply_block(&mut state, block, vec![tx_ref(create_tx, BlockHash::from_u64_word(5002), 0, 0)], &auth_inputs);

        let mut snapshot =
            state.export_snapshot(block, 77, BlockHash::from_u64_word(1), &[block]).expect("snapshot export must succeed");
        snapshot.state.state_hash_by_block.insert(BlockHash::from_u64_word(9999), [9u8; 32]);

        let mut recovered = AtomicTokenState::new(1, network);
        let err = recovered.import_snapshot(snapshot).expect_err("snapshot import must fail");
        assert!(matches!(err, AtomicTokenError::Processing(message) if message.contains("state_hash_by_block")));
    }

    #[test]
    fn conformance_event_id_golden_vector() {
        let state = AtomicTokenState::new(1, "cryptix-simnet".to_string());
        let event_id = state.compute_event_id(
            BlockHash::from_u64_word(1000),
            BlockHash::from_u64_word(2000),
            EventType::Applied,
            ApplyStatus::Applied,
            NoopReason::None,
            3,
        );
        assert_eq!(to_hex(&event_id), "79cf538d0a8adb0e976192502c9227a8cf59cf564d89dde65c0eaf5d3680b9cb");
    }

    #[test]
    fn conformance_acceptance_normalization_preserves_consensus_order() {
        let script = test_script(7);
        let outpoint = TransactionOutpoint::new(BlockHash::from_u64_word(555), 0);

        let tx_a = token_tx(outpoint, script.clone(), payload_burn(0, 1, [1u8; 32], 1));
        let tx_b = token_tx(outpoint, script.clone(), payload_burn(0, 1, [2u8; 32], 1));
        let tx_c = token_tx(outpoint, script, payload_burn(0, 1, [3u8; 32], 1));

        let a = tx_ref(tx_a, BlockHash::from_u64_word(3), 4, 2);
        let b = tx_ref(tx_b, BlockHash::from_u64_word(1), 1, 1);
        let c = tx_ref(tx_c, BlockHash::from_u64_word(2), 1, 1);

        let normalized = normalize_acceptance_refs(BlockHash::from_u64_word(999), vec![a.clone(), b.clone(), c.clone(), b.clone()])
            .expect("normalization should succeed");

        assert!(normalized.conflicting_txids.is_empty());
        assert_eq!(normalized.refs.len(), 3);
        assert_eq!(normalized.refs[0].txid, a.txid);
        assert_eq!(normalized.refs[1].txid, b.txid);
        assert_eq!(normalized.refs[2].txid, c.txid);
    }

    #[test]
    fn conformance_acceptance_normalization_deduplicates_without_reordering() {
        let script = test_script(17);
        let outpoint = TransactionOutpoint::new(BlockHash::from_u64_word(556), 0);

        let tx_a = token_tx(outpoint, script.clone(), payload_burn(0, 1, [4u8; 32], 1));
        let tx_b = token_tx(outpoint, script, payload_burn(0, 1, [5u8; 32], 1));

        let a_late = tx_ref(tx_a.clone(), BlockHash::from_u64_word(10), 0, 99);
        let a_early = tx_ref(tx_a, BlockHash::from_u64_word(10), 0, 1);
        let b = tx_ref(tx_b, BlockHash::from_u64_word(2), 0, 50);

        let normalized = normalize_acceptance_refs(BlockHash::from_u64_word(999), vec![a_late.clone(), b.clone(), a_early])
            .expect("normalization should succeed");

        assert!(normalized.conflicting_txids.is_empty());
        assert_eq!(normalized.refs.len(), 2);
        assert_eq!(normalized.refs[0].txid, a_late.txid);
        assert_eq!(normalized.refs[1].txid, b.txid);
    }

    #[test]
    fn conformance_acceptance_normalization_rejects_conflicts() {
        let script = test_script(19);
        let outpoint = TransactionOutpoint::new(BlockHash::from_u64_word(777), 0);
        let tx = token_tx(outpoint, script, payload_burn(0, 1, [4u8; 32], 1));
        let base = tx_ref(tx.clone(), BlockHash::from_u64_word(1), 2, 0);
        let conflict = CanonicalTxRef {
            txid: base.txid,
            source_block_hash: BlockHash::from_u64_word(5),
            source_block_daa_score: 0,
            source_block_time: 0,
            tx_index: 9,
            acceptance_entry_position: 0,
            tx,
        };

        let normalized = normalize_acceptance_refs(BlockHash::from_u64_word(888), vec![base, conflict]).unwrap();
        assert_eq!(normalized.refs.len(), 1);
        assert_eq!(normalized.conflicting_txids.len(), 1);
    }

    #[test]
    fn conformance_state_machine_mint_transfer_burn_reorg_snapshot_recovery() {
        let network = "cryptix-simnet".to_string();
        let mut state = AtomicTokenState::new(1, network.clone());
        let owner_script = test_script(3);
        let receiver_script = test_script(101);
        let owner = owner_id(&state, &owner_script);
        let receiver = owner_id(&state, &receiver_script);

        let outpoint1 = TransactionOutpoint::new(BlockHash::from_u64_word(10), 0);
        let outpoint2 = TransactionOutpoint::new(BlockHash::from_u64_word(11), 0);
        let outpoint3 = TransactionOutpoint::new(BlockHash::from_u64_word(12), 0);
        let outpoint4 = TransactionOutpoint::new(BlockHash::from_u64_word(13), 0);

        let mut auth_inputs = HashMap::new();
        auth_inputs.insert(outpoint1, UtxoEntry::new(1000, owner_script.clone(), 0, false));
        auth_inputs.insert(outpoint2, UtxoEntry::new(1000, owner_script.clone(), 0, false));
        auth_inputs.insert(outpoint3, UtxoEntry::new(1000, owner_script.clone(), 0, false));
        auth_inputs.insert(outpoint4, UtxoEntry::new(1000, owner_script.clone(), 0, false));

        let create_tx = token_tx(outpoint1, owner_script.clone(), payload_create_asset(0, 1, 8, owner, b"Token", b"TKN", b"\x01\x02"));
        let asset_id = hash_bytes(create_tx.id());

        let mint_tx = token_tx(outpoint2, owner_script.clone(), payload_mint(0, 1, asset_id, owner, 1000));
        let transfer_tx = token_tx(outpoint3, owner_script.clone(), payload_transfer(0, 2, asset_id, receiver, 300));
        let burn_tx = token_tx(outpoint4, owner_script.clone(), payload_burn(0, 3, asset_id, 200));

        let block1 = BlockHash::from_u64_word(100);
        let block2 = BlockHash::from_u64_word(101);
        let refs_block1 = vec![
            tx_ref(create_tx.clone(), BlockHash::from_u64_word(200), 0, 0),
            tx_ref(mint_tx.clone(), BlockHash::from_u64_word(200), 1, 0),
        ];
        let refs_block2 = vec![
            tx_ref(transfer_tx.clone(), BlockHash::from_u64_word(201), 0, 0),
            tx_ref(burn_tx.clone(), BlockHash::from_u64_word(201), 1, 0),
        ];

        apply_block(&mut state, block1, refs_block1.clone(), &auth_inputs);
        apply_block(&mut state, block2, refs_block2.clone(), &auth_inputs);

        let asset = state.get_asset(asset_id).expect("asset should exist");
        assert_eq!(asset.total_supply, 800);
        assert_eq!(state.get_balance(asset_id, owner), 500);
        assert_eq!(state.get_balance(asset_id, receiver), 300);
        assert_eq!(state.get_owner_nonce(owner), 2);
        assert_eq!(state.get_token_nonce(owner, asset_id), 4);
        assert_eq!(state.processed_ops.len(), 4);
        assert_eq!(state.events.len(), 4);
        assert!(state.events.iter().all(|e| matches!(e.event_type, EventType::Applied)));

        let pre_snapshot_hash = state.compute_state_hash();
        let snapshot =
            state.export_snapshot(block2, 1234, BlockHash::from_u64_word(1), &[block1, block2]).expect("snapshot export must succeed");

        state.rollback_block(block2).expect("rollback block2");
        assert_eq!(state.get_balance(asset_id, owner), 1000);
        assert_eq!(state.get_balance(asset_id, receiver), 0);
        state.rollback_block(block1).expect("rollback block1");
        assert!(state.get_asset(asset_id).is_none());
        assert_eq!(state.events.len(), 8);
        assert!(state.events.iter().any(|e| matches!(e.event_type, EventType::Reorged)));

        let mut recovered = AtomicTokenState::new(1, network);
        recovered.import_snapshot(snapshot.clone()).expect("snapshot import should succeed");
        recovered
            .rollback_snapshot_window_to_parent(snapshot.window_start_block_hash)
            .expect("snapshot rollback window should succeed");
        apply_block(&mut recovered, block1, refs_block1, &auth_inputs);
        apply_block(&mut recovered, block2, refs_block2, &auth_inputs);

        assert_eq!(recovered.compute_state_hash(), pre_snapshot_hash);
        assert_eq!(recovered.compute_state_hash(), snapshot.state_hash_at_fp);
        assert_eq!(recovered.events.len(), snapshot.state.events.len());
        assert_eq!(recovered.get_balance(asset_id, owner), 500);
        assert_eq!(recovered.get_balance(asset_id, receiver), 300);
    }

    #[test]
    fn conformance_snapshot_recovery_rollback_replay_is_state_stable() {
        let network = "cryptix-simnet".to_string();
        let mut state = AtomicTokenState::new(1, network.clone());
        let owner_script = test_script(33);
        let receiver_script = test_script(77);
        let owner = owner_id(&state, &owner_script);
        let receiver = owner_id(&state, &receiver_script);

        let outpoint1 = TransactionOutpoint::new(BlockHash::from_u64_word(301), 0);
        let outpoint2 = TransactionOutpoint::new(BlockHash::from_u64_word(302), 0);
        let outpoint3 = TransactionOutpoint::new(BlockHash::from_u64_word(303), 0);
        let outpoint4 = TransactionOutpoint::new(BlockHash::from_u64_word(304), 0);

        let mut auth_inputs = HashMap::new();
        auth_inputs.insert(outpoint1, UtxoEntry::new(1000, owner_script.clone(), 0, false));
        auth_inputs.insert(outpoint2, UtxoEntry::new(1000, owner_script.clone(), 0, false));
        auth_inputs.insert(outpoint3, UtxoEntry::new(1000, owner_script.clone(), 0, false));
        auth_inputs.insert(outpoint4, UtxoEntry::new(1000, owner_script.clone(), 0, false));

        let create_tx =
            token_tx(outpoint1, owner_script.clone(), payload_create_asset(0, 1, 8, owner, b"StableToken", b"STB", b"\xAA"));
        let asset_id = hash_bytes(create_tx.id());
        let mint_tx = token_tx(outpoint2, owner_script.clone(), payload_mint(0, 2, asset_id, owner, 1000));
        let transfer_tx = token_tx(outpoint3, owner_script.clone(), payload_transfer(0, 3, asset_id, receiver, 250));
        let burn_tx = token_tx(outpoint4, owner_script.clone(), payload_burn(0, 4, asset_id, 125));

        let block1 = BlockHash::from_u64_word(401);
        let block2 = BlockHash::from_u64_word(402);
        let refs_block1 = vec![
            tx_ref(create_tx.clone(), BlockHash::from_u64_word(9001), 0, 0),
            tx_ref(mint_tx.clone(), BlockHash::from_u64_word(9001), 1, 0),
        ];
        let refs_block2 = vec![
            tx_ref(transfer_tx.clone(), BlockHash::from_u64_word(9002), 0, 0),
            tx_ref(burn_tx.clone(), BlockHash::from_u64_word(9002), 1, 0),
        ];

        apply_block(&mut state, block1, refs_block1.clone(), &auth_inputs);
        apply_block(&mut state, block2, refs_block2.clone(), &auth_inputs);

        let snapshot = state
            .export_snapshot(block2, 2222, BlockHash::from_u64_word(1111), &[block1, block2])
            .expect("snapshot export must succeed");
        let expected_state_hash = snapshot.state_hash_at_fp;
        let expected_event_count = snapshot.state.events.len();
        let expected_event_fingerprint = snapshot
            .state
            .events
            .iter()
            .map(|event| {
                (
                    event.event_id,
                    event.sequence,
                    event.accepting_block_hash,
                    event.txid,
                    event.event_type,
                    event.apply_status,
                    event.noop_reason,
                    event.ordinal,
                    event.reorg_of_event_id,
                )
            })
            .collect::<Vec<_>>();

        let mut recovered = AtomicTokenState::new(1, network);
        recovered.import_snapshot(snapshot.clone()).expect("snapshot import should succeed");

        for _ in 0..2 {
            recovered
                .rollback_snapshot_window_to_parent(snapshot.window_start_block_hash)
                .expect("snapshot rollback window should succeed");
            apply_block(&mut recovered, block1, refs_block1.clone(), &auth_inputs);
            apply_block(&mut recovered, block2, refs_block2.clone(), &auth_inputs);

            assert_eq!(recovered.compute_state_hash(), expected_state_hash);
            assert_eq!(recovered.events.len(), expected_event_count);
            let recovered_event_fingerprint = recovered
                .events
                .iter()
                .map(|event| {
                    (
                        event.event_id,
                        event.sequence,
                        event.accepting_block_hash,
                        event.txid,
                        event.event_type,
                        event.apply_status,
                        event.noop_reason,
                        event.ordinal,
                        event.reorg_of_event_id,
                    )
                })
                .collect::<Vec<_>>();
            assert_eq!(recovered_event_fingerprint, expected_event_fingerprint);

            let unique_event_ids = recovered.events.iter().map(|event| event.event_id).collect::<std::collections::HashSet<_>>();
            assert_eq!(unique_event_ids.len(), recovered.events.len(), "rollback+replay must not duplicate event ids");
        }
    }

    #[test]
    fn stress_reorg_snapshot_replay_matches_fresh_state() {
        let network = "cryptix-simnet".to_string();
        let owner_script = test_script(41);
        let alice_script = test_script(42);
        let bob_script = test_script(43);
        let owner = owner_id(&AtomicTokenState::new(1, network.clone()), &owner_script);
        let alice = owner_id(&AtomicTokenState::new(1, network.clone()), &alice_script);
        let bob = owner_id(&AtomicTokenState::new(1, network.clone()), &bob_script);

        let mut auth_inputs = HashMap::new();
        let mut next_outpoint_tag = 6_000u64;
        let mut make_tx = |script: &ScriptPublicKey, payload: Vec<u8>| {
            let outpoint = TransactionOutpoint::new(BlockHash::from_u64_word(next_outpoint_tag), 0);
            next_outpoint_tag += 1;
            auth_inputs.insert(outpoint, UtxoEntry::new(10_000, script.clone(), 0, false));
            token_tx(outpoint, script.clone(), payload)
        };

        let create_tx = make_tx(&owner_script, payload_create_asset(0, 1, 8, owner, b"StressToken", b"STR", b""));
        let asset_id = hash_bytes(create_tx.id());
        let mint_tx = make_tx(&owner_script, payload_mint(0, 1, asset_id, owner, 10_000));
        let owner_to_alice_tx = make_tx(&owner_script, payload_transfer(0, 2, asset_id, alice, 800));
        let owner_to_bob_tx = make_tx(&owner_script, payload_transfer(0, 3, asset_id, bob, 500));
        let alice_to_bob_tx = make_tx(&alice_script, payload_transfer(0, 1, asset_id, bob, 300));
        let bob_to_alice_tx = make_tx(&bob_script, payload_transfer(0, 1, asset_id, alice, 125));
        let owner_burn_tx = make_tx(&owner_script, payload_burn(0, 4, asset_id, 400));

        let owner_mint_a_tx = make_tx(&owner_script, payload_mint(0, 5, asset_id, owner, 600));
        let alice_burn_a_tx = make_tx(&alice_script, payload_burn(0, 2, asset_id, 50));
        let bob_to_owner_a_tx = make_tx(&bob_script, payload_transfer(0, 2, asset_id, owner, 250));

        let owner_burn_b_tx = make_tx(&owner_script, payload_burn(0, 5, asset_id, 300));
        let alice_to_owner_b_tx = make_tx(&alice_script, payload_transfer(0, 2, asset_id, owner, 75));
        let bob_burn_b_tx = make_tx(&bob_script, payload_burn(0, 2, asset_id, 125));

        let block1 = BlockHash::from_u64_word(7_001);
        let block2 = BlockHash::from_u64_word(7_002);
        let block3 = BlockHash::from_u64_word(7_003);
        let block4a = BlockHash::from_u64_word(7_004);
        let block4b = BlockHash::from_u64_word(7_104);
        let refs1 = vec![
            tx_ref(create_tx.clone(), BlockHash::from_u64_word(8_001), 0, 0),
            tx_ref(mint_tx.clone(), BlockHash::from_u64_word(8_001), 1, 0),
        ];
        let refs2 = vec![
            tx_ref(owner_to_alice_tx.clone(), BlockHash::from_u64_word(8_002), 0, 0),
            tx_ref(owner_to_bob_tx.clone(), BlockHash::from_u64_word(8_002), 1, 0),
        ];
        let refs3 = vec![
            tx_ref(alice_to_bob_tx.clone(), BlockHash::from_u64_word(8_003), 0, 0),
            tx_ref(bob_to_alice_tx.clone(), BlockHash::from_u64_word(8_003), 1, 0),
            tx_ref(owner_burn_tx.clone(), BlockHash::from_u64_word(8_003), 2, 0),
        ];
        let refs4a = vec![
            tx_ref(owner_mint_a_tx.clone(), BlockHash::from_u64_word(8_004), 0, 0),
            tx_ref(alice_burn_a_tx.clone(), BlockHash::from_u64_word(8_004), 1, 0),
            tx_ref(bob_to_owner_a_tx.clone(), BlockHash::from_u64_word(8_004), 2, 0),
        ];
        let refs4b = vec![
            tx_ref(owner_burn_b_tx.clone(), BlockHash::from_u64_word(8_104), 0, 0),
            tx_ref(alice_to_owner_b_tx.clone(), BlockHash::from_u64_word(8_104), 1, 0),
            tx_ref(bob_burn_b_tx.clone(), BlockHash::from_u64_word(8_104), 2, 0),
        ];

        let mut canonical = AtomicTokenState::new(1, network.clone());
        apply_block(&mut canonical, block1, refs1.clone(), &auth_inputs);
        apply_block(&mut canonical, block2, refs2.clone(), &auth_inputs);
        apply_block(&mut canonical, block3, refs3.clone(), &auth_inputs);
        apply_block(&mut canonical, block4a, refs4a.clone(), &auth_inputs);
        assert!(!canonical.degraded);
        assert_eq!(canonical.get_balance(asset_id, owner), 9_150);
        assert_eq!(canonical.get_balance(asset_id, alice), 575);
        assert_eq!(canonical.get_balance(asset_id, bob), 425);
        assert_eq!(canonical.get_asset(asset_id).expect("asset").total_supply, 10_150);

        let snapshot_a = canonical
            .export_snapshot(block4a, 9_004, BlockHash::from_u64_word(9_999), &[block1, block2, block3, block4a])
            .expect("canonical snapshot export should succeed");

        canonical.rollback_block(block4a).expect("rollback canonical tip");
        apply_block(&mut canonical, block4b, refs4b.clone(), &auth_inputs);
        assert!(!canonical.degraded);

        let mut fresh_alt = AtomicTokenState::new(1, network.clone());
        apply_block(&mut fresh_alt, block1, refs1.clone(), &auth_inputs);
        apply_block(&mut fresh_alt, block2, refs2.clone(), &auth_inputs);
        apply_block(&mut fresh_alt, block3, refs3.clone(), &auth_inputs);
        apply_block(&mut fresh_alt, block4b, refs4b.clone(), &auth_inputs);

        assert_eq!(canonical.compute_state_hash(), fresh_alt.compute_state_hash());
        assert_eq!(canonical.get_balance(asset_id, owner), 8_075);
        assert_eq!(canonical.get_balance(asset_id, alice), 550);
        assert_eq!(canonical.get_balance(asset_id, bob), 550);
        assert_eq!(canonical.get_asset(asset_id).expect("asset").total_supply, 9_175);
        assert_eq!(canonical.get_token_nonce(owner, asset_id), 6);
        assert_eq!(canonical.get_token_nonce(alice, asset_id), 3);
        assert_eq!(canonical.get_token_nonce(bob, asset_id), 3);

        let snapshot_b = canonical
            .export_snapshot(block4b, 9_104, BlockHash::from_u64_word(9_999), &[block1, block2, block3, block4b])
            .expect("alternative snapshot export should succeed");
        let mut recovered = AtomicTokenState::new(1, network);
        recovered.import_snapshot(snapshot_b.clone()).expect("snapshot import should succeed");
        recovered.rollback_snapshot_window_to_parent(snapshot_b.window_start_block_hash).expect("snapshot rollback should succeed");
        apply_block(&mut recovered, block1, refs1, &auth_inputs);
        apply_block(&mut recovered, block2, refs2, &auth_inputs);
        apply_block(&mut recovered, block3, refs3, &auth_inputs);
        apply_block(&mut recovered, block4b, refs4b, &auth_inputs);
        assert_eq!(recovered.compute_state_hash(), fresh_alt.compute_state_hash());
        assert_ne!(snapshot_a.state_hash_at_fp, snapshot_b.state_hash_at_fp);
    }

    #[test]
    fn repeated_reorg_reaccept_events_remain_append_only() {
        let mut state = AtomicTokenState::new(1, "cryptix-simnet".to_string());
        let owner_script = test_script(17);
        let owner = owner_id(&state, &owner_script);

        let outpoint = TransactionOutpoint::new(BlockHash::from_u64_word(700), 0);
        let mut auth_inputs = HashMap::new();
        auth_inputs.insert(outpoint, UtxoEntry::new(1000, owner_script.clone(), 0, false));

        let create_tx = token_tx(outpoint, owner_script.clone(), payload_create_asset(0, 1, 8, owner, b"Loop", b"LOP", b""));
        let block = BlockHash::from_u64_word(701);
        let refs = vec![tx_ref(create_tx, BlockHash::from_u64_word(702), 0, 0)];

        apply_block(&mut state, block, refs.clone(), &auth_inputs);
        assert_eq!(state.events.len(), 1);
        let first_applied_id = state.events[0].event_id;

        state.rollback_block(block).expect("first rollback should succeed");
        assert_eq!(state.events.len(), 2);
        let first_reorg_id = state.events[1].event_id;

        apply_block(&mut state, block, refs, &auth_inputs);
        assert_eq!(state.events.len(), 3);
        let second_applied_id = state.events[2].event_id;
        assert_ne!(second_applied_id, first_applied_id);

        state.rollback_block(block).expect("second rollback should succeed");
        assert_eq!(state.events.len(), 4);
        let second_reorg_id = state.events[3].event_id;
        assert_ne!(second_reorg_id, first_reorg_id);

        let sequences = state.events.iter().map(|event| event.sequence).collect::<Vec<_>>();
        assert_eq!(sequences, vec![1, 2, 3, 4]);
    }
}
