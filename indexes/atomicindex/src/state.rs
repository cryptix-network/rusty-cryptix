use crate::{
    error::{AtomicTokenError, AtomicTokenResult},
    liquidity_math::{
        calculate_trade_fee, cpmm_buy, cpmm_sell, initial_virtual_token_reserves, LiquidityMathError,
        INITIAL_REAL_CPAY_RESERVES_SOMPI, INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI, LIQUIDITY_MIN_PAYOUT_SOMPI, LIQUIDITY_TOKEN_DECIMALS,
        MAX_LIQUIDITY_SUPPLY_RAW, MIN_CPAY_RESERVE_SOMPI, MIN_LIQUIDITY_SEED_RESERVE_SOMPI, MIN_LIQUIDITY_SUPPLY_RAW,
        MIN_REAL_TOKEN_RESERVE,
    },
    payload::{
        parse_atomic_token_payload, ApplyStatus, BuyLiquidityExactInOp, ClaimLiquidityFeesOp, CreateAssetOp, CreateAssetWithMintOp,
        CreateLiquidityAssetOp, EventType, LiquidityRecipientAddress, MintOp, NoopReason, ParsedTokenPayload, SellLiquidityExactInOp,
        SupplyMode, TokenOp, TokenOpCode,
    },
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
use cryptix_txscript::script_class::ScriptClass;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

const CAT_OWNER_DOMAIN: &[u8] = b"CAT_OWNER_V2";
const OWNER_AUTH_SCHEME_PUBKEY: u8 = 0;
const OWNER_AUTH_SCHEME_PUBKEY_ECDSA: u8 = 1;
const OWNER_AUTH_SCHEME_SCRIPT_HASH: u8 = 2;
const CAT_STATE_DOMAIN: &[u8] = b"CRYPTIX_ATOMIC_STATE_V1";

const SECTION_ASSETS: u8 = 0xA1;
const SECTION_BALANCES: u8 = 0xB1;
const SECTION_NONCES: u8 = 0xC1;
const SECTION_ANCHOR_COUNTS: u8 = 0xD1;
const CAT_EVENT_DOMAIN: &[u8] = b"CAT_EVT_V1";
const CAT_EVENT_INSTANCE_DOMAIN: &[u8] = b"CAT_EVT_INSTANCE_V1";
pub const SNAPSHOT_SCHEMA_VERSION: u16 = 1;

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
    pub nonces: HashMap<[u8; 32], u64>,
    pub anchor_counts: HashMap<[u8; 32], u64>,
    pub processed_ops: HashMap<BlockHash, ProcessedOp>,
    pub known_owner_addresses: HashMap<[u8; 32], LiquidityHolderAddressState>,
}

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AtomicTokenSnapshotState {
    pub assets: HashMap<[u8; 32], TokenAsset>,
    pub balances: HashMap<BalanceKey, u128>,
    pub nonces: HashMap<[u8; 32], u64>,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenAsset {
    pub asset_id: [u8; 32],
    pub creator_owner_id: [u8; 32],
    #[serde(default)]
    pub asset_class: TokenAssetClass,
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
    pub owner_id: [u8; 32],
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
    seen_nonces: HashSet<[u8; 32]>,
    seen_anchor_counts: HashSet<[u8; 32]>,
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
    tx_index: u32,
    acceptance_entry_position: u32,
    tx: Transaction,
}

struct NormalizedAcceptance {
    refs: Vec<CanonicalTxRef>,
    conflicting_txids: HashSet<BlockHash>,
}

fn normalize_acceptance_refs(_accepting_block_hash: BlockHash, refs: Vec<CanonicalTxRef>) -> AtomicTokenResult<NormalizedAcceptance> {
    let mut seen_semantics: HashMap<BlockHash, (BlockHash, u32, u32)> = HashMap::new();
    let mut unique_refs = Vec::with_capacity(refs.len());
    let mut conflicting_txids = HashSet::new();

    for tx_ref in refs {
        let semantics = (tx_ref.source_block_hash, tx_ref.tx_index, tx_ref.acceptance_entry_position);
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

    unique_refs.sort_by(|a, b| {
        a.acceptance_entry_position
            .cmp(&b.acceptance_entry_position)
            .then(a.tx_index.cmp(&b.tx_index))
            .then(a.txid.as_bytes().cmp(&b.txid.as_bytes()))
    });
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
    pub nonces: HashMap<[u8; 32], u64>,
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
        }
    }

    pub fn set_payload_hf_activation_daa_score(&mut self, daa_score: u64) {
        self.payload_hf_activation_daa_score = daa_score;
    }

    pub fn rebuild_runtime_caches(&mut self) {
        self.rebuild_liquidity_vault_outpoint_index();
        self.rebuild_known_owner_address_cache();
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
        self.known_owner_addresses.clear();
        let mut remembered = Vec::new();
        for asset in self.assets.values() {
            let Some(pool) = asset.liquidity.as_ref() else {
                continue;
            };
            for recipient in pool.fee_recipients.iter() {
                remembered.push((
                    recipient.owner_id,
                    LiquidityHolderAddressState {
                        address_version: recipient.address_version,
                        address_payload: recipient.address_payload.clone(),
                    },
                ));
            }
            for (owner_id, holder) in pool.holder_addresses.iter() {
                remembered.push((*owner_id, holder.clone()));
            }
        }
        for (owner_id, holder) in remembered {
            self.known_owner_addresses.entry(owner_id).or_insert(holder);
        }
    }

    fn remember_owner_address(&mut self, owner_id: [u8; 32], address_version: u8, address_payload: &[u8]) {
        self.known_owner_addresses
            .entry(owner_id)
            .or_insert_with(|| LiquidityHolderAddressState { address_version, address_payload: address_payload.to_vec() });
    }

    fn set_asset_state(&mut self, asset_id: [u8; 32], asset: TokenAsset) {
        if let Some(previous_asset) = self.assets.insert(asset_id, asset.clone()) {
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

    pub fn mark_degraded(&mut self) {
        self.degraded = true;
        self.live_correct = false;
    }

    pub fn has_verified_state(&self) -> bool {
        self.applied_chain_order.last().is_some()
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

    pub async fn apply_virtual_chain_change(
        &mut self,
        notification: &VirtualChainChangedNotification,
        auth_inputs: &HashMap<TransactionOutpoint, UtxoEntry>,
        consensus_manager: &Arc<ConsensusManager>,
    ) -> AtomicTokenResult<()> {
        if self.degraded {
            return Ok(());
        }

        for removed_block_hash in notification.removed_chain_block_hashes.iter().copied() {
            if self.rollback_block(removed_block_hash).is_err() {
                self.mark_degraded();
                return Err(AtomicTokenError::Processing(format!(
                    "Cryptix Atomic cannot rollback block `{removed_block_hash}` because journal is missing"
                )));
            }
        }

        let consensus = consensus_manager.consensus();
        let session = consensus.session().await;

        for (idx, accepting_block_hash) in notification.added_chain_block_hashes.iter().copied().enumerate() {
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
                let state_hash = self.compute_state_hash();
                self.block_journals.insert(accepting_block_hash, journal.into_block_journal());
                self.state_hash_by_block.insert(accepting_block_hash, state_hash);
                self.event_sequence_by_block.insert(accepting_block_hash, self.next_event_sequence);
                self.applied_chain_order.push(accepting_block_hash);
                self.mark_degraded();
                return Err(AtomicTokenError::Degraded(format!(
                    "malformed acceptance data for accepting block `{accepting_block_hash}`: duplicate txid with incompatible semantics"
                )));
            }

            for (ordinal, tx_ref) in normalized.refs.into_iter().enumerate() {
                self.apply_transaction(
                    accepting_block_hash,
                    accepting_header.daa_score,
                    accepting_header.timestamp,
                    &tx_ref,
                    ordinal as u32,
                    auth_inputs,
                    &mut journal,
                );
                self.apply_anchor_deltas_for_tx(&tx_ref.tx, auth_inputs, &mut journal);
            }

            let state_hash = self.compute_state_hash();
            self.block_journals.insert(accepting_block_hash, journal.into_block_journal());
            self.state_hash_by_block.insert(accepting_block_hash, state_hash);
            self.event_sequence_by_block.insert(accepting_block_hash, self.next_event_sequence);
            self.applied_chain_order.push(accepting_block_hash);
        }

        self.live_correct = !self.degraded;
        Ok(())
    }

    pub fn prune_history(&mut self, max_retained_blocks: usize) {
        if max_retained_blocks == 0 {
            return;
        }
        if self.applied_chain_order.len() <= max_retained_blocks {
            return;
        }

        let prune_len = self.applied_chain_order.len().saturating_sub(max_retained_blocks);
        let pruned_hashes: Vec<BlockHash> = self.applied_chain_order.drain(..prune_len).collect();
        let pruned_hashes_set = pruned_hashes.iter().copied().collect::<HashSet<_>>();
        let last_pruned_event_sequence =
            pruned_hashes.iter().filter_map(|block_hash| self.event_sequence_by_block.get(block_hash).copied()).max();

        for block_hash in pruned_hashes {
            self.block_journals.remove(&block_hash);
            self.state_hash_by_block.remove(&block_hash);
            self.event_sequence_by_block.remove(&block_hash);
        }

        self.processed_ops.retain(|_, op| !pruned_hashes_set.contains(&op.accepting_block_hash));

        if let Some(last_pruned_event_sequence) = last_pruned_event_sequence {
            self.events.retain(|event| event.sequence > last_pruned_event_sequence);
            self.rebuild_event_id_index();
        }
    }

    fn rollback_block(&mut self, block_hash: BlockHash) -> Result<(), ()> {
        self.rollback_block_internal(block_hash, true)
    }

    fn rollback_block_internal(&mut self, block_hash: BlockHash, emit_reorg_events: bool) -> Result<(), ()> {
        let journal = self.block_journals.remove(&block_hash).ok_or(())?;

        for change in journal.changed_assets.iter().rev() {
            match &change.old_value {
                Some(asset) => {
                    self.assets.insert(change.asset_id, asset.clone());
                }
                None => {
                    self.assets.remove(&change.asset_id);
                }
            }
        }
        self.rebuild_liquidity_vault_outpoint_index();

        for change in journal.changed_balances.iter().rev() {
            match change.old_value {
                Some(value) => {
                    self.balances.insert(change.key, value);
                }
                None => {
                    self.balances.remove(&change.key);
                }
            }
        }

        for change in journal.changed_nonces.iter().rev() {
            match change.old_value {
                Some(value) => {
                    self.nonces.insert(change.owner_id, value);
                }
                None => {
                    self.nonces.remove(&change.owner_id);
                }
            }
        }

        for change in journal.changed_anchor_counts.iter().rev() {
            match change.old_value {
                Some(value) => {
                    self.anchor_counts.insert(change.owner_id, value);
                }
                None => {
                    self.anchor_counts.remove(&change.owner_id);
                }
            }
        }

        for txid in journal.added_processed_ops {
            self.processed_ops.remove(&txid);
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
        Ok(())
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
        let mut block_cache: HashMap<BlockHash, Arc<Vec<Transaction>>> = HashMap::new();
        let mut refs: Vec<CanonicalTxRef> = Vec::new();

        for (acceptance_entry_position, mergeset_entry) in acceptance_data.iter().enumerate() {
            let txs = if let Some(txs) = block_cache.get(&mergeset_entry.block_hash) {
                txs.clone()
            } else {
                let block = session.async_get_block(mergeset_entry.block_hash).await?;
                let txs = block.transactions;
                block_cache.insert(mergeset_entry.block_hash, txs.clone());
                txs
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
        accepting_block_time: u64,
        tx_ref: &CanonicalTxRef,
        ordinal: u32,
        auth_inputs: &HashMap<TransactionOutpoint, UtxoEntry>,
        journal: &mut JournalBuilder,
    ) {
        let tx = &tx_ref.tx;
        if accepting_block_daa_score < self.payload_hf_activation_daa_score {
            return;
        }
        if !tx.subnetwork_id.is_payload() || tx.payload.is_empty() {
            return;
        }

        let parsed = match parse_atomic_token_payload(&tx.payload) {
            Some(value) => value,
            None => return,
        };

        if self.processed_ops.contains_key(&tx.id()) {
            return;
        }

        match parsed {
            Ok(parsed) => {
                let result = self.execute_parsed_op(
                    tx,
                    &parsed,
                    auth_inputs,
                    accepting_block_hash,
                    accepting_block_daa_score,
                    accepting_block_time,
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
                    Err(_noop_reason) => {
                        // Accepted CAT ops that fail execution semantics indicate
                        // consensus/index divergence. Fail closed.
                        self.mark_degraded();
                        let details = self.build_event_details(tx, &parsed, auth_inputs);
                        self.insert_processed(
                            tx.id(),
                            accepting_block_hash,
                            ApplyStatus::Noop,
                            NoopReason::InternalMalformedAcceptance,
                            tx_ref.source_block_hash,
                            ordinal,
                            details,
                            journal,
                        );
                    }
                }
            }
            Err(_noop_reason) => {
                // Accepted CAT payload parse failures are consensus/index divergence.
                // We preserve journal continuity but force degraded runtime state.
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
    }

    fn execute_parsed_op(
        &mut self,
        tx: &Transaction,
        parsed: &ParsedTokenPayload,
        auth_inputs: &HashMap<TransactionOutpoint, UtxoEntry>,
        accepting_block_hash: BlockHash,
        accepting_block_daa_score: u64,
        accepting_block_time: u64,
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
        let expected_nonce = self.nonces.get(&owner_id).copied().unwrap_or(1);
        if parsed.header.nonce != expected_nonce {
            return Err(NoopReason::BadNonce);
        }
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
                accepting_block_hash,
                accepting_block_daa_score,
                accepting_block_time,
                journal,
            )?,
            TokenOp::CreateAssetWithMint(op) => self.execute_create_asset_with_mint(
                tx.id().as_bytes(),
                owner_id,
                op,
                accepting_block_hash,
                accepting_block_daa_score,
                accepting_block_time,
                journal,
            )?,
            TokenOp::CreateLiquidityAsset(op) => {
                let token_out = self.execute_create_liquidity_asset(
                    tx,
                    &auth_context,
                    op,
                    accepting_block_hash,
                    accepting_block_daa_score,
                    accepting_block_time,
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

        self.record_nonce_before(owner_id, journal);
        self.nonces.insert(owner_id, expected_nonce + 1);
        Ok(details)
    }

    fn validate_replacement_anchor(
        &self,
        tx: &Transaction,
        auth_context: &AuthContext,
        auth_inputs: &HashMap<TransactionOutpoint, UtxoEntry>,
    ) -> Result<(), NoopReason> {
        let owner_id = auth_context.owner_id;
        let before_count = self.anchor_counts.get(&owner_id).copied().unwrap_or(0);
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
            let old_count = self.anchor_counts.get(&owner_id).copied().unwrap_or(0);
            let spent = spent_counts.get(&owner_id).copied().unwrap_or(0);
            let created = created_counts.get(&owner_id).copied().unwrap_or(0);
            let new_count = old_count.saturating_sub(spent).saturating_add(created);
            if new_count == old_count {
                continue;
            }

            self.record_anchor_count_before(owner_id, journal);
            if new_count == 0 {
                self.anchor_counts.remove(&owner_id);
            } else {
                self.anchor_counts.insert(owner_id, new_count);
            }
        }
    }

    fn execute_create_asset(
        &mut self,
        txid_bytes: [u8; 32],
        creator_owner_id: [u8; 32],
        op: &CreateAssetOp,
        accepting_block_hash: BlockHash,
        accepting_block_daa_score: u64,
        accepting_block_time: u64,
        journal: &mut JournalBuilder,
    ) -> Result<(), NoopReason> {
        if self.assets.contains_key(&txid_bytes) {
            return Err(NoopReason::AssetAlreadyExists);
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
                mint_authority_owner_id: op.mint_authority_owner_id,
                decimals: op.decimals,
                supply_mode: op.supply_mode,
                max_supply: op.max_supply,
                total_supply: 0,
                name: op.name.clone(),
                symbol: op.symbol.clone(),
                metadata: op.metadata.clone(),
                platform_tag: op.platform_tag.clone(),
                created_block_hash: Some(accepting_block_hash),
                created_daa_score: Some(accepting_block_daa_score),
                created_at: Some(accepting_block_time),
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
        accepting_block_hash: BlockHash,
        accepting_block_daa_score: u64,
        accepting_block_time: u64,
        journal: &mut JournalBuilder,
    ) -> Result<(), NoopReason> {
        let create = CreateAssetOp {
            decimals: op.decimals,
            supply_mode: op.supply_mode,
            max_supply: op.max_supply,
            mint_authority_owner_id: op.mint_authority_owner_id,
            name: op.name.clone(),
            symbol: op.symbol.clone(),
            metadata: op.metadata.clone(),
            platform_tag: op.platform_tag.clone(),
        };
        self.execute_create_asset(
            txid_bytes,
            creator_owner_id,
            &create,
            accepting_block_hash,
            accepting_block_daa_score,
            accepting_block_time,
            journal,
        )?;

        if op.initial_mint_amount > 0 {
            let mint = MintOp { asset_id: txid_bytes, to_owner_id: op.initial_mint_to_owner_id, amount: op.initial_mint_amount };
            self.execute_mint(op.mint_authority_owner_id, &mint, journal)?;
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

        let mut asset = self.assets.get(&asset_id).cloned().ok_or(NoopReason::AssetNotFound)?;
        let is_liquidity_asset = matches!(asset.asset_class, TokenAssetClass::Liquidity);
        if is_liquidity_asset {
            self.validate_liquidity_invariants(&asset)?;
        }

        let from_key = BalanceKey { asset_id, owner_id: from_owner_id };
        let to_key = BalanceKey { asset_id, owner_id: to_owner_id };

        if from_key == to_key {
            // Self-transfers are valid nonce-bearing ops but must not mutate balances.
            let sender_balance = self.balances.get(&from_key).copied().unwrap_or(0);
            sender_balance.checked_sub(amount).ok_or(NoopReason::InsufficientBalance)?;
            return Ok(());
        }

        let sender_balance = self.balances.get(&from_key).copied().unwrap_or(0);
        let receiver_balance = self.balances.get(&to_key).copied().unwrap_or(0);

        let sender_after = sender_balance.checked_sub(amount).ok_or(NoopReason::InsufficientBalance)?;
        let receiver_after = receiver_balance.checked_add(amount).ok_or(NoopReason::BalanceOverflow)?;

        self.record_balance_before(from_key, journal);
        self.record_balance_before(to_key, journal);

        if sender_after == 0 {
            self.balances.remove(&from_key);
        } else {
            self.balances.insert(from_key, sender_after);
        }

        self.balances.insert(to_key, receiver_after);
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

        let mut asset = self.assets.get(&op.asset_id).cloned().ok_or(NoopReason::AssetNotFound)?;
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
        let receiver_balance = self.balances.get(&receiver_key).copied().unwrap_or(0);
        let receiver_after = receiver_balance.checked_add(op.amount).ok_or(NoopReason::BalanceOverflow)?;

        self.record_asset_before(op.asset_id, journal);
        self.record_balance_before(receiver_key, journal);

        asset.total_supply = new_total_supply;
        self.set_asset_state(op.asset_id, asset);
        self.balances.insert(receiver_key, receiver_after);
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

        let mut asset = self.assets.get(&asset_id).cloned().ok_or(NoopReason::AssetNotFound)?;
        if matches!(asset.asset_class, TokenAssetClass::Liquidity) {
            return Err(NoopReason::LegacyOpForLiquidityAsset);
        }
        let sender_key = BalanceKey { asset_id, owner_id: sender_owner_id };
        let sender_balance = self.balances.get(&sender_key).copied().unwrap_or(0);

        let sender_after = sender_balance.checked_sub(amount).ok_or(NoopReason::InsufficientBalance)?;
        let supply_after = asset.total_supply.checked_sub(amount).ok_or(NoopReason::SupplyUnderflow)?;

        self.record_asset_before(asset_id, journal);
        self.record_balance_before(sender_key, journal);

        asset.total_supply = supply_after;
        self.set_asset_state(asset_id, asset);
        if sender_after == 0 {
            self.balances.remove(&sender_key);
        } else {
            self.balances.insert(sender_key, sender_after);
        }
        Ok(())
    }

    fn execute_create_liquidity_asset(
        &mut self,
        tx: &Transaction,
        creator_auth: &AuthContext,
        op: &CreateLiquidityAssetOp,
        accepting_block_hash: BlockHash,
        accepting_block_daa_score: u64,
        accepting_block_time: u64,
        journal: &mut JournalBuilder,
    ) -> Result<u128, NoopReason> {
        let creator_owner_id = creator_auth.owner_id;
        let asset_id = tx.id().as_bytes();
        if self.assets.contains_key(&asset_id) {
            return Err(NoopReason::AssetAlreadyExists);
        }
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
        let mut virtual_cpay_reserves_sompi = INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI;
        let mut virtual_token_reserves = initial_virtual_token_reserves(op.max_supply).map_err(|_| NoopReason::BadMaxSupply)?;
        let mut unclaimed_fee_total_sompi = 0u64;
        let mut total_supply = 0u128;
        let mut holder_addresses: HashMap<[u8; 32], LiquidityHolderAddressState> = HashMap::new();

        if op.launch_buy_sompi > 0 {
            let fee_trade = calculate_trade_fee(op.launch_buy_sompi, op.fee_bps).map_err(map_liquidity_math_error)?;
            let launch_buy_net = op.launch_buy_sompi.checked_sub(fee_trade).ok_or(NoopReason::SupplyUnderflow)?;
            let (token_out, new_real_token_reserves, new_virtual_cpay_reserves_sompi, new_virtual_token_reserves) =
                cpmm_buy(real_token_reserves, virtual_cpay_reserves_sompi, virtual_token_reserves, launch_buy_net)
                    .map_err(map_liquidity_math_error)?;
            if token_out < op.launch_buy_min_token_out {
                return Err(NoopReason::MinOutViolation);
            }
            real_cpay_reserves_sompi = real_cpay_reserves_sompi.checked_add(launch_buy_net).ok_or(NoopReason::SupplyOverflow)?;
            real_token_reserves = new_real_token_reserves;
            virtual_cpay_reserves_sompi = new_virtual_cpay_reserves_sompi;
            virtual_token_reserves = new_virtual_token_reserves;
            self.apply_fee_to_pool(&mut fee_recipients, &mut unclaimed_fee_total_sompi, fee_trade)?;
            total_supply = token_out;

            let receiver_key = BalanceKey { asset_id, owner_id: creator_owner_id };
            self.record_balance_before(receiver_key, journal);
            let receiver_balance = self.balances.get(&receiver_key).copied().unwrap_or(0);
            let receiver_after = receiver_balance.checked_add(token_out).ok_or(NoopReason::BalanceOverflow)?;
            self.balances.insert(receiver_key, receiver_after);
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
            mint_authority_owner_id: [0u8; 32],
            decimals: op.decimals,
            supply_mode: SupplyMode::Capped,
            max_supply: op.max_supply,
            total_supply,
            name: op.name.clone(),
            symbol: op.symbol.clone(),
            metadata: op.metadata.clone(),
            platform_tag: op.platform_tag.clone(),
            created_block_hash: Some(accepting_block_hash),
            created_daa_score: Some(accepting_block_daa_score),
            created_at: Some(accepting_block_time),
            liquidity: Some(LiquidityPoolState {
                pool_nonce: 1,
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
        let mut asset = self.assets.get(&op.asset_id).cloned().ok_or(NoopReason::AssetNotFound)?;
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

        let receiver_balance = self.balances.get(&receiver_key).copied().unwrap_or(0);
        let receiver_after = receiver_balance.checked_add(token_out).ok_or(NoopReason::BalanceOverflow)?;
        self.balances.insert(receiver_key, receiver_after);

        asset.total_supply = asset.total_supply.checked_add(token_out).ok_or(NoopReason::SupplyOverflow)?;
        asset.liquidity = Some(pool);
        self.validate_liquidity_invariants(&asset)?;
        self.set_asset_state(op.asset_id, asset);
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
        let mut asset = self.assets.get(&op.asset_id).cloned().ok_or(NoopReason::AssetNotFound)?;
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
        let sender_balance = self.balances.get(&sender_key).copied().unwrap_or(0);
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
            self.balances.remove(&sender_key);
            pool.holder_addresses.remove(&seller_owner_id);
        } else {
            self.balances.insert(sender_key, sender_after);
        }

        asset.total_supply = supply_after;
        asset.liquidity = Some(pool);
        self.validate_liquidity_invariants(&asset)?;
        self.set_asset_state(op.asset_id, asset);
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
        let mut asset = self.assets.get(&op.asset_id).cloned().ok_or(NoopReason::AssetNotFound)?;
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
            let asset = self.assets.get(&asset_id).ok_or(NoopReason::InternalMalformedAcceptance)?;
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
        self.processed_ops.insert(txid, ProcessedOp { accepting_block_hash, apply_status, noop_reason });
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
        if self.processed_ops.contains_key(&tx.id()) {
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
            journal.changed_assets.push(ChangedAsset { asset_id, old_value: self.assets.get(&asset_id).cloned() });
        }
    }

    fn record_balance_before(&mut self, key: BalanceKey, journal: &mut JournalBuilder) {
        if journal.seen_balances.insert(key) {
            journal.changed_balances.push(ChangedBalance { key, old_value: self.balances.get(&key).copied() });
        }
    }

    fn record_nonce_before(&mut self, owner_id: [u8; 32], journal: &mut JournalBuilder) {
        if journal.seen_nonces.insert(owner_id) {
            journal.changed_nonces.push(ChangedNonce { owner_id, old_value: self.nonces.get(&owner_id).copied() });
        }
    }

    fn record_anchor_count_before(&mut self, owner_id: [u8; 32], journal: &mut JournalBuilder) {
        if journal.seen_anchor_counts.insert(owner_id) {
            journal.changed_anchor_counts.push(ChangedAnchorCount { owner_id, old_value: self.anchor_counts.get(&owner_id).copied() });
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
        self.balances.get(&BalanceKey { asset_id, owner_id }).copied().unwrap_or(0)
    }

    pub fn get_nonce(&self, owner_id: [u8; 32]) -> u64 {
        self.nonces.get(&owner_id).copied().unwrap_or(1)
    }

    pub fn get_asset(&self, asset_id: [u8; 32]) -> Option<TokenAsset> {
        self.assets.get(&asset_id).cloned()
    }

    pub fn get_op_status(&self, txid: BlockHash) -> Option<ProcessedOp> {
        self.processed_ops.get(&txid).cloned()
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
                        nonces.insert(change.owner_id, value);
                    }
                    None => {
                        nonces.remove(&change.owner_id);
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

        let state_hash = self.state_hash_by_block.get(&at_block_hash).copied()?;
        let event_sequence_cutoff = self.event_sequence_by_block.get(&at_block_hash).copied().unwrap_or(self.next_event_sequence);
        Some(AtomicTokenReadView {
            at_block_hash,
            state_hash,
            is_degraded: self.degraded,
            runtime_state: self.runtime_state(false),
            event_sequence_cutoff,
            assets,
            balances,
            nonces,
            anchor_counts,
            processed_ops,
            known_owner_addresses: self.known_owner_addresses.clone(),
        })
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
        let applied_chain_order = self.applied_chain_order[..=target_index].to_vec();
        let state_hash_by_block: HashMap<BlockHash, [u8; 32]> = applied_chain_order
            .iter()
            .filter_map(|hash| self.state_hash_by_block.get(hash).copied().map(|state_hash| (*hash, state_hash)))
            .collect();
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

        Ok(AtomicTokenSnapshot {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            protocol_version: self.protocol_version,
            network_id: self.network_id.clone(),
            at_block_hash,
            at_daa_score,
            state_hash_at_fp: view.state_hash,
            state_hash_at_window_start_parent: self.state_hash_by_block.get(&window_start_parent_block_hash).copied(),
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

        let trusted_processed_ops = Self::rebuild_processed_ops_from_snapshot_window(&snapshot.journals_in_window)?;
        let AtomicTokenSnapshot { state, journals_in_window, .. } = snapshot;
        let AtomicTokenSnapshotState {
            assets,
            balances,
            nonces,
            anchor_counts,
            processed_ops: _,
            state_hash_by_block,
            event_sequence_by_block,
            applied_chain_order,
            next_event_sequence: _,
            events: _,
        } = state;

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
        // Never trust snapshot-supplied processed/event history that is not committed by state_hash_at_fp.
        self.processed_ops = trusted_processed_ops;
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

    fn rebuild_processed_ops_from_snapshot_window(
        journals_in_window: &[(BlockHash, BlockJournal)],
    ) -> AtomicTokenResult<HashMap<BlockHash, ProcessedOp>> {
        let mut trusted = HashMap::new();
        for (accepting_block_hash, journal) in journals_in_window.iter() {
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
                let previous = trusted.insert(
                    txid,
                    ProcessedOp {
                        accepting_block_hash: *accepting_block_hash,
                        apply_status: tx_result.apply_status,
                        noop_reason: tx_result.noop_reason,
                    },
                );
                if previous.is_some() {
                    return Err(AtomicTokenError::Processing(format!(
                        "snapshot import failed: duplicate processed txid `{txid}` in rollback window journals"
                    )));
                }
            }
        }
        Ok(trusted)
    }

    pub fn compute_state_hash(&self) -> [u8; 32] {
        let network_id_bytes = self.network_id.as_bytes();
        let network_len = u16::try_from(network_id_bytes.len()).unwrap_or(0);

        let mut hasher = Blake2bParams::new().hash_length(32).to_state();
        hasher.update(CAT_STATE_DOMAIN);
        hasher.update(&self.protocol_version.to_le_bytes());
        hasher.update(&network_len.to_le_bytes());
        hasher.update(network_id_bytes);

        self.hash_assets_section(&mut hasher);
        self.hash_balances_section(&mut hasher);
        self.hash_nonces_section(&mut hasher);
        self.hash_anchor_counts_section(&mut hasher);

        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_bytes());
        out
    }

    fn hash_assets_section(&self, hasher: &mut blake2b_simd::State) {
        hasher.update(&[SECTION_ASSETS]);

        let mut asset_ids: Vec<[u8; 32]> = self.assets.keys().copied().collect();
        asset_ids.sort_unstable();
        hasher.update(&(asset_ids.len() as u32).to_le_bytes());

        for asset_id in asset_ids {
            if let Some(asset) = self.assets.get(&asset_id) {
                hasher.update(&asset.asset_id);
                hasher.update(&asset.creator_owner_id);
                hasher.update(&[asset.asset_class as u8]);
                hasher.update(&asset.mint_authority_owner_id);
                hasher.update(&[asset.decimals]);
                hasher.update(&[asset.supply_mode as u8]);
                hasher.update(&asset.max_supply.to_le_bytes());
                hasher.update(&asset.total_supply.to_le_bytes());
                hasher.update(&[asset.name.len() as u8]);
                hasher.update(&asset.name);
                hasher.update(&[asset.symbol.len() as u8]);
                hasher.update(&asset.symbol);
                hasher.update(&(asset.metadata.len() as u16).to_le_bytes());
                hasher.update(&asset.metadata);
                hasher.update(&[asset.platform_tag.len() as u8]);
                hasher.update(&asset.platform_tag);
                if let Some(pool) = asset.liquidity.as_ref() {
                    hasher.update(&[1u8]);
                    hasher.update(&pool.pool_nonce.to_le_bytes());
                    hasher.update(&pool.real_cpay_reserves_sompi.to_le_bytes());
                    hasher.update(&pool.real_token_reserves.to_le_bytes());
                    hasher.update(&pool.virtual_cpay_reserves_sompi.to_le_bytes());
                    hasher.update(&pool.virtual_token_reserves.to_le_bytes());
                    hasher.update(&pool.unclaimed_fee_total_sompi.to_le_bytes());
                    hasher.update(&pool.fee_bps.to_le_bytes());
                    hasher.update(&(pool.fee_recipients.len() as u8).to_le_bytes());
                    for recipient in pool.fee_recipients.iter() {
                        hasher.update(&recipient.owner_id);
                        hasher.update(&[recipient.address_version]);
                        hasher.update(&[recipient.address_payload.len() as u8]);
                        hasher.update(&recipient.address_payload);
                        hasher.update(&recipient.unclaimed_sompi.to_le_bytes());
                    }
                    let mut holder_ids: Vec<[u8; 32]> = pool.holder_addresses.keys().copied().collect();
                    holder_ids.sort_unstable();
                    hasher.update(&(holder_ids.len() as u32).to_le_bytes());
                    for holder_id in holder_ids {
                        if let Some(holder_address) = pool.holder_addresses.get(&holder_id) {
                            hasher.update(&holder_id);
                            hasher.update(&[holder_address.address_version]);
                            hasher.update(&[holder_address.address_payload.len() as u8]);
                            hasher.update(&holder_address.address_payload);
                        }
                    }
                    hasher.update(&pool.vault_outpoint.transaction_id.as_bytes());
                    hasher.update(&pool.vault_outpoint.index.to_le_bytes());
                    hasher.update(&pool.vault_value_sompi.to_le_bytes());
                    hasher.update(&pool.unlock_target_sompi.to_le_bytes());
                    hasher.update(&[u8::from(pool.unlocked)]);
                } else {
                    hasher.update(&[0u8]);
                }
            }
        }
    }

    fn hash_balances_section(&self, hasher: &mut blake2b_simd::State) {
        hasher.update(&[SECTION_BALANCES]);
        let mut keys: Vec<BalanceKey> = self.balances.keys().copied().collect();
        keys.sort_unstable();
        hasher.update(&(keys.len() as u32).to_le_bytes());

        for key in keys {
            if let Some(amount) = self.balances.get(&key) {
                hasher.update(&key.asset_id);
                hasher.update(&key.owner_id);
                hasher.update(&amount.to_le_bytes());
            }
        }
    }

    fn hash_nonces_section(&self, hasher: &mut blake2b_simd::State) {
        hasher.update(&[SECTION_NONCES]);
        let mut owners: Vec<[u8; 32]> = self.nonces.keys().copied().collect();
        owners.sort_unstable();
        hasher.update(&(owners.len() as u32).to_le_bytes());

        for owner in owners {
            if let Some(nonce) = self.nonces.get(&owner) {
                hasher.update(&owner);
                hasher.update(&nonce.to_le_bytes());
            }
        }
    }

    fn hash_anchor_counts_section(&self, hasher: &mut blake2b_simd::State) {
        hasher.update(&[SECTION_ANCHOR_COUNTS]);
        let mut owners: Vec<[u8; 32]> = self.anchor_counts.keys().copied().collect();
        owners.sort_unstable();
        hasher.update(&(owners.len() as u32).to_le_bytes());

        for owner in owners {
            if let Some(anchor_count) = self.anchor_counts.get(&owner) {
                hasher.update(&owner);
                hasher.update(&anchor_count.to_le_bytes());
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::TokenOpCode;
    use cryptix_consensus_core::{
        constants::TX_VERSION,
        subnets::SUBNETWORK_ID_PAYLOAD,
        tx::{ScriptVec, TransactionInput, TransactionOutput},
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
        let txid = tx.id();
        CanonicalTxRef { txid, source_block_hash, tx_index, acceptance_entry_position, tx }
    }

    fn apply_block(
        state: &mut AtomicTokenState,
        accepting_block_hash: BlockHash,
        refs: Vec<CanonicalTxRef>,
        auth_inputs: &HashMap<TransactionOutpoint, UtxoEntry>,
    ) {
        let mut journal = JournalBuilder::default();
        for (ordinal, tx_ref) in refs.iter().enumerate() {
            state.apply_transaction(accepting_block_hash, 0, 0, tx_ref, ordinal as u32, auth_inputs, &mut journal);
            state.apply_anchor_deltas_for_tx(&tx_ref.tx, auth_inputs, &mut journal);
        }
        state.block_journals.insert(accepting_block_hash, journal.into_block_journal());
        state.state_hash_by_block.insert(accepting_block_hash, state.compute_state_hash());
        state.event_sequence_by_block.insert(accepting_block_hash, state.next_event_sequence);
        state.applied_chain_order.push(accepting_block_hash);
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
        state.nonces.insert(owner, 7);

        let hash = state.compute_state_hash();
        let hash_hex = to_hex(&hash);
        assert_eq!(hash_hex, "82adad80dcc568b7e71b2ca202bf43d0f7b199425a8a3ee8ab18b065ee5a4ed4");
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
    fn state_hash_commits_liquidity_holder_addresses() {
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
        assert_ne!(before, after);
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
        let launch_buy_sompi = 10 * MIN_LIQUIDITY_SEED_RESERVE_SOMPI;
        let launch_min = 1u128;
        let launch_token_out = cpmm_buy(
            max_supply,
            INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI,
            crate::liquidity_math::INITIAL_VIRTUAL_TOKEN_RESERVES,
            launch_buy_sompi,
        )
        .expect("launch quote should work")
        .0;

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
        let buy_in_sompi = 10 * MIN_LIQUIDITY_SEED_RESERVE_SOMPI;
        let buy_token_out =
            cpmm_buy(pool.real_token_reserves, pool.virtual_cpay_reserves_sompi, pool.virtual_token_reserves, buy_in_sompi)
                .expect("buy quote should work")
                .0;
        let buy_auth_outpoint = TransactionOutpoint::new(BlockHash::from_u64_word(2), 0);
        let buy_payload = payload_buy_liquidity(1, 2, asset_id, pool.pool_nonce, buy_in_sompi, 1);
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
    fn liquidity_lock_blocks_outflows_until_buy_reaches_target_then_stays_unlocked() {
        let mut state = AtomicTokenState::new(1, "cryptix-simnet".to_string());
        let owner_script = test_script(33);
        let owner_payload = vec![0x33; 32];
        let owner = state.owner_id_from_address_components(0, owner_payload.as_slice()).expect("owner id should derive");
        let asset_id = [0x44; 32];
        let vault_outpoint = TransactionOutpoint::new(BlockHash::from_u64_word(44), 0);
        let buy_in_sompi = 10 * MIN_LIQUIDITY_SEED_RESERVE_SOMPI;
        let target = MIN_LIQUIDITY_SEED_RESERVE_SOMPI + buy_in_sompi;

        state.assets.insert(
            asset_id,
            TokenAsset {
                asset_id,
                creator_owner_id: owner,
                asset_class: TokenAssetClass::Liquidity,
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
    fn state_hash_ignores_processed_ops() {
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
            &tx_ref(create_tx.clone(), BlockHash::from_u64_word(7001), 0, 0),
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
        assert_eq!(asset.created_block_hash, Some(BlockHash::from_u64_word(6001)));
        assert_eq!(asset.created_daa_score, Some(123_456));
        assert_eq!(asset.created_at, Some(1_715_123_000_000));

        let transfer_event = state.events.iter().find(|event| event.txid == transfer_tx.id()).expect("transfer event should exist");
        assert_eq!(transfer_event.details.op_type, Some(TokenOpCode::Transfer));
        assert_eq!(transfer_event.details.asset_id, Some(asset_id));
        assert_eq!(transfer_event.details.from_owner_id, Some(owner));
        assert_eq!(transfer_event.details.to_owner_id, Some(receiver));
        assert_eq!(transfer_event.details.amount, Some(125));
    }

    #[test]
    fn import_snapshot_drops_unbound_history_fields() {
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
        recovered.import_snapshot(snapshot).expect("snapshot import should succeed");

        assert_eq!(recovered.compute_state_hash(), expected_state_hash);
        assert_eq!(recovered.events.len(), 0);
        assert_eq!(recovered.next_event_sequence, 0);
        assert!(!recovered.processed_ops.contains_key(&poisoned_txid));
        assert_eq!(recovered.processed_ops.keys().copied().collect::<HashSet<_>>(), expected_window_txids);
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
        assert_eq!(to_hex(&event_id), "21220baf58aacf015053fe5d86544bf015613e93c69ec268b9c19938ad7e4f5d");
    }

    #[test]
    fn conformance_acceptance_normalization_golden_vector() {
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
        assert_eq!(normalized.refs[0].txid, b.txid);
        assert_eq!(normalized.refs[1].txid, c.txid);
        assert_eq!(normalized.refs[2].txid, a.txid);
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

        let mint_tx = token_tx(outpoint2, owner_script.clone(), payload_mint(0, 2, asset_id, owner, 1000));
        let transfer_tx = token_tx(outpoint3, owner_script.clone(), payload_transfer(0, 3, asset_id, receiver, 300));
        let burn_tx = token_tx(outpoint4, owner_script.clone(), payload_burn(0, 4, asset_id, 200));

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
        assert_eq!(state.get_nonce(owner), 5);
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
