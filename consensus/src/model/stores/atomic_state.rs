use blake2b_simd::Params as Blake2bParams;
use cryptix_consensus_core::BlockHasher;
use cryptix_consensus_core::ChainPath;
use cryptix_consensus_core::{constants::MAX_SOMPI, tx::TransactionOutpoint};
use cryptix_database::prelude::CachePolicy;
use cryptix_database::prelude::DbKey;
use cryptix_database::prelude::StoreError;
use cryptix_database::prelude::DB;
use cryptix_database::prelude::{BatchDbWriter, CachedDbAccess};
use cryptix_database::registry::DatabaseStorePrefixes;
use cryptix_hashes::Hash;
use cryptix_utils::mem_size::MemSizeEstimator;
use rocksdb::WriteBatch;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::mem::size_of;
use std::sync::Arc;

const ATOMIC_CONSENSUS_STATE_HASH_DOMAIN: &[u8] = b"cryptix-atomic-consensus-state-root-v2";
const ATOMIC_STATE_COMMITMENT_DOMAIN: &[u8] = b"cryptix-utxo-atomic-state-commitment-v1";
const ATOMIC_STATE_ROOT_SUBPREFIX: u8 = b'R';
const ATOMIC_STATE_DELTA_SUBPREFIX: u8 = b'D';
const ATOMIC_STATE_CURRENT_META_SUBPREFIX: u8 = b'M';
const ATOMIC_STATE_CURRENT_NONCE_SUBPREFIX: u8 = b'n';
const ATOMIC_STATE_CURRENT_ASSET_SUBPREFIX: u8 = b'a';
const ATOMIC_STATE_CURRENT_BALANCE_SUBPREFIX: u8 = b'b';
const ATOMIC_STATE_CURRENT_ANCHOR_SUBPREFIX: u8 = b'c';
const ATOMIC_STATE_CURRENT_VAULT_SUBPREFIX: u8 = b'v';
const ATOMIC_STATE_CURRENT_ROOT_KEY: &[u8] = b"current-root";
const ATOMIC_CONSENSUS_STATE_MAGIC: &[u8] = b"CATCSG02";
const ATOMIC_CONSENSUS_STATE_ROOT_ONLY_TAG: &[u8] = b"ROOT";
const ATOMIC_CONSENSUS_ROOT_ACCUMULATOR_VERSION: u8 = 2;
const ATOMIC_ROOT_NAMESPACE_NONCE: u8 = b'n';
const ATOMIC_ROOT_NAMESPACE_ASSET: u8 = b'a';
const ATOMIC_ROOT_NAMESPACE_BALANCE: u8 = b'b';
const ATOMIC_ROOT_NAMESPACE_ANCHOR: u8 = b'c';
const ATOMIC_P2P_ROOT_BUCKETS: usize = 4096;
const ATOMIC_P2P_ROOT_LEAF_DOMAIN: &[u8] = b"CRYPTIX_ATOMIC_V2_LEAF";
const ATOMIC_P2P_ROOT_BUCKET_DOMAIN: &[u8] = b"CRYPTIX_ATOMIC_V2_BUCKETED_ROOT";
const ATOMIC_P2P_ROOT_BUCKET_INDEX_DOMAIN: &[u8] = b"CRYPTIX_ATOMIC_V2_BUCKET_INDEX";
const ATOMIC_P2P_ASSET_ROOT_V1: &[u8] = b"CAT_ASSET_P2P_AUDIT_ROOT_V1";
const ATOMIC_P2P_LOGICAL_ASSET: u8 = 0x01;
const ATOMIC_P2P_LOGICAL_BALANCE: u8 = 0x02;
const ATOMIC_P2P_LOGICAL_NONCE: u8 = 0x03;
pub const ATOMIC_CURRENT_TOKEN_VERSION: u8 = 1;
pub const ATOMIC_CURRENT_LIQUIDITY_CURVE_VERSION: u8 = 1;
pub const ATOMIC_LIQUIDITY_CURVE_MODE_BASIC: u8 = 0;
pub const ATOMIC_LIQUIDITY_CURVE_MODE_AGGRESSIVE: u8 = 1;
pub const ATOMIC_LIQUIDITY_CURVE_MODE_INDIVIDUAL: u8 = 2;
pub const ATOMIC_DEFAULT_LIQUIDITY_CURVE_MODE: u8 = ATOMIC_LIQUIDITY_CURVE_MODE_BASIC;
const ATOMIC_INDIVIDUAL_MIN_VIRTUAL_CPAY_RESERVES_SOMPI: u64 = 100_000_000_000_000;
const ATOMIC_INDIVIDUAL_MAX_VIRTUAL_CPAY_RESERVES_SOMPI: u64 = 800_000_000_000_000;
const ATOMIC_INDIVIDUAL_VIRTUAL_CPAY_STEP_SOMPI: u64 = 10_000_000_000_000;
const ATOMIC_INDIVIDUAL_MIN_VIRTUAL_TOKEN_MULTIPLIER_BPS: u16 = 10_100;
const ATOMIC_INDIVIDUAL_MAX_VIRTUAL_TOKEN_MULTIPLIER_BPS: u16 = 20_000;
const ATOMIC_INDIVIDUAL_VIRTUAL_TOKEN_MULTIPLIER_STEP_BPS: u16 = 100;
const ATOMIC_MAX_TOKEN_VERSION: u8 = 99;
const ATOMIC_MAX_LIQUIDITY_CURVE_VERSION: u8 = 99;
const ATOMIC_OWNER_DOMAIN: &[u8] = b"CAT_OWNER_V2";
const OWNER_AUTH_SCHEME_PUBKEY: u8 = 0;
const OWNER_AUTH_SCHEME_PUBKEY_ECDSA: u8 = 1;
const OWNER_AUTH_SCHEME_SCRIPT_HASH: u8 = 2;
const MAX_ATOMIC_LIQUIDITY_FEE_RECIPIENTS: usize = 2;
const MIN_ATOMIC_LIQUIDITY_FEE_BPS: u16 = 10;
const MAX_ATOMIC_LIQUIDITY_FEE_BPS: u16 = 1000;
const MAX_ATOMIC_PLATFORM_TAG_LEN: usize = 50;
const MAX_ATOMIC_NAME_LEN: usize = 32;
const MAX_ATOMIC_SYMBOL_LEN: usize = 10;
const MAX_ATOMIC_METADATA_LEN: usize = 256;
const MAX_ATOMIC_DECIMALS: u8 = 18;
pub const ATOMIC_NONCE_SCOPE_OWNER: u8 = 0;
pub const ATOMIC_NONCE_SCOPE_ASSET: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AtomicBalanceKey {
    pub asset_id: [u8; 32],
    pub owner_id: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AtomicNonceKey {
    pub owner_id: [u8; 32],
    pub scope_kind: u8,
    pub scope_id: [u8; 32],
}

impl AtomicNonceKey {
    pub fn owner(owner_id: [u8; 32]) -> Self {
        Self { owner_id, scope_kind: ATOMIC_NONCE_SCOPE_OWNER, scope_id: [0u8; 32] }
    }

    pub fn asset(owner_id: [u8; 32], asset_id: [u8; 32]) -> Self {
        Self { owner_id, scope_kind: ATOMIC_NONCE_SCOPE_ASSET, scope_id: asset_id }
    }

    pub fn validate(&self) -> Result<(), String> {
        match self.scope_kind {
            ATOMIC_NONCE_SCOPE_OWNER => {
                if self.scope_id == [0u8; 32] {
                    Ok(())
                } else {
                    Err(format!(
                        "owner nonce scope for owner `{}` has non-zero scope id `{}`",
                        faster_hex::hex_string(&self.owner_id),
                        faster_hex::hex_string(&self.scope_id)
                    ))
                }
            }
            ATOMIC_NONCE_SCOPE_ASSET => {
                if self.scope_id != [0u8; 32] {
                    Ok(())
                } else {
                    Err(format!("asset nonce scope for owner `{}` has zero asset id", faster_hex::hex_string(&self.owner_id)))
                }
            }
            _ => Err(format!(
                "atomic nonce for owner `{}` has invalid scope kind `{}`",
                faster_hex::hex_string(&self.owner_id),
                self.scope_kind
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AtomicSupplyMode {
    Uncapped,
    Capped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AtomicAssetClass {
    #[default]
    Standard,
    Liquidity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomicLiquidityFeeRecipientState {
    pub owner_id: [u8; 32],
    pub address_version: u8,
    pub address_payload: Vec<u8>,
    pub unclaimed_sompi: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomicLiquidityPoolState {
    pub pool_nonce: u64,
    #[serde(default = "default_atomic_liquidity_curve_version")]
    pub curve_version: u8,
    #[serde(default = "default_atomic_liquidity_curve_mode")]
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
    pub fee_recipients: Vec<AtomicLiquidityFeeRecipientState>,
    pub vault_outpoint: TransactionOutpoint,
    pub vault_value_sompi: u64,
    #[serde(default)]
    pub unlock_target_sompi: u64,
    #[serde(default = "default_atomic_liquidity_unlocked")]
    pub unlocked: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomicAssetState {
    #[serde(default)]
    pub creator_owner_id: [u8; 32],
    #[serde(default)]
    pub asset_class: AtomicAssetClass,
    #[serde(default = "default_atomic_token_version")]
    pub token_version: u8,
    pub mint_authority_owner_id: [u8; 32],
    #[serde(default)]
    pub decimals: u8,
    pub supply_mode: AtomicSupplyMode,
    pub max_supply: u128,
    pub total_supply: u128,
    #[serde(default)]
    pub name: Vec<u8>,
    #[serde(default)]
    pub symbol: Vec<u8>,
    #[serde(default)]
    pub metadata: Vec<u8>,
    #[serde(default)]
    pub platform_tag: Vec<u8>,
    #[serde(default)]
    pub created_block_hash: Option<[u8; 32]>,
    #[serde(default)]
    pub created_daa_score: Option<u64>,
    #[serde(default)]
    pub created_at: Option<u64>,
    #[serde(default)]
    pub liquidity: Option<AtomicLiquidityPoolState>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AtomicConsensusState {
    #[serde(skip)]
    pub next_nonces: HashMap<AtomicNonceKey, u64>,
    #[serde(skip)]
    pub assets: HashMap<[u8; 32], AtomicAssetState>,
    #[serde(skip)]
    pub balances: HashMap<AtomicBalanceKey, u128>,
    #[serde(skip)]
    pub anchor_counts: HashMap<[u8; 32], u64>,
    #[serde(skip)]
    pub liquidity_vault_outpoints: HashMap<TransactionOutpoint, [u8; 32]>,
    #[serde(default)]
    root_accumulator: AtomicConsensusRootAccumulator,
    #[serde(skip)]
    delta_tracking: bool,
    #[serde(skip)]
    dirty_delta: AtomicConsensusStateDeltaBuilder,
    #[serde(skip)]
    current_store: Option<Arc<DbAtomicStateStore>>,
    #[serde(skip)]
    deleted_nonces: HashSet<AtomicNonceKey>,
    #[serde(skip)]
    deleted_assets: HashSet<[u8; 32]>,
    #[serde(skip)]
    deleted_balances: HashSet<AtomicBalanceKey>,
    #[serde(skip)]
    deleted_anchor_counts: HashSet<[u8; 32]>,
    #[serde(skip)]
    deleted_vault_outpoints: HashSet<TransactionOutpoint>,
}

impl Default for AtomicConsensusState {
    fn default() -> Self {
        Self {
            next_nonces: HashMap::new(),
            assets: HashMap::new(),
            balances: HashMap::new(),
            anchor_counts: HashMap::new(),
            liquidity_vault_outpoints: HashMap::new(),
            root_accumulator: AtomicConsensusRootAccumulator::default(),
            delta_tracking: false,
            dirty_delta: AtomicConsensusStateDeltaBuilder::default(),
            current_store: None,
            deleted_nonces: HashSet::new(),
            deleted_assets: HashSet::new(),
            deleted_balances: HashSet::new(),
            deleted_anchor_counts: HashSet::new(),
            deleted_vault_outpoints: HashSet::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomicConsensusRootAccumulator {
    version: u8,
    nonce_count: u64,
    nonce_xor: [u8; 32],
    asset_count: u64,
    asset_xor: [u8; 32],
    balance_count: u64,
    balance_xor: [u8; 32],
    anchor_count: u64,
    anchor_xor: [u8; 32],
}

impl Default for AtomicConsensusRootAccumulator {
    fn default() -> Self {
        Self {
            version: ATOMIC_CONSENSUS_ROOT_ACCUMULATOR_VERSION,
            nonce_count: 0,
            nonce_xor: [0; 32],
            asset_count: 0,
            asset_xor: [0; 32],
            balance_count: 0,
            balance_xor: [0; 32],
            anchor_count: 0,
            anchor_xor: [0; 32],
        }
    }
}

impl AtomicConsensusRootAccumulator {
    pub fn nonce_count(&self) -> u64 {
        self.nonce_count
    }

    pub fn asset_count(&self) -> u64 {
        self.asset_count
    }

    pub fn balance_count(&self) -> u64 {
        self.balance_count
    }

    pub fn anchor_count(&self) -> u64 {
        self.anchor_count
    }

    fn from_state_maps(state: &AtomicConsensusState) -> Self {
        let mut root = Self::default();
        for (key, value) in state.next_nonces.iter() {
            root.apply_nonce(key, None, Some(*value));
        }
        for (asset_id, asset) in state.assets.iter() {
            root.apply_asset(asset_id, None, Some(asset));
        }
        for (key, value) in state.balances.iter() {
            root.apply_balance(key, None, Some(*value));
        }
        for (owner_id, value) in state.anchor_counts.iter() {
            root.apply_anchor_count(owner_id, None, Some(*value));
        }
        root
    }

    fn hash(&self) -> [u8; 32] {
        let mut hasher = Blake2bParams::new().hash_length(32).to_state();
        hasher.update(ATOMIC_CONSENSUS_STATE_HASH_DOMAIN);
        hash_u8(&mut hasher, self.version);

        hash_u8(&mut hasher, ATOMIC_ROOT_NAMESPACE_NONCE);
        hash_u64(&mut hasher, self.nonce_count);
        hasher.update(&self.nonce_xor);

        hash_u8(&mut hasher, ATOMIC_ROOT_NAMESPACE_ASSET);
        hash_u64(&mut hasher, self.asset_count);
        hasher.update(&self.asset_xor);

        hash_u8(&mut hasher, ATOMIC_ROOT_NAMESPACE_BALANCE);
        hash_u64(&mut hasher, self.balance_count);
        hasher.update(&self.balance_xor);

        hash_u8(&mut hasher, ATOMIC_ROOT_NAMESPACE_ANCHOR);
        hash_u64(&mut hasher, self.anchor_count);
        hasher.update(&self.anchor_xor);

        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_bytes());
        out
    }

    fn apply_nonce(&mut self, key: &AtomicNonceKey, old_value: Option<u64>, new_value: Option<u64>) {
        self.apply_entry(
            ATOMIC_ROOT_NAMESPACE_NONCE,
            old_value.map(|value| hash_nonce_entry(key, value)),
            new_value.map(|value| hash_nonce_entry(key, value)),
        );
    }

    fn apply_asset(&mut self, asset_id: &[u8; 32], old_value: Option<&AtomicAssetState>, new_value: Option<&AtomicAssetState>) {
        self.apply_entry(
            ATOMIC_ROOT_NAMESPACE_ASSET,
            old_value.map(|value| hash_asset_entry(asset_id, value)),
            new_value.map(|value| hash_asset_entry(asset_id, value)),
        );
    }

    fn apply_balance(&mut self, key: &AtomicBalanceKey, old_value: Option<u128>, new_value: Option<u128>) {
        self.apply_entry(
            ATOMIC_ROOT_NAMESPACE_BALANCE,
            old_value.map(|value| hash_balance_entry(key, value)),
            new_value.map(|value| hash_balance_entry(key, value)),
        );
    }

    fn apply_anchor_count(&mut self, owner_id: &[u8; 32], old_value: Option<u64>, new_value: Option<u64>) {
        self.apply_entry(
            ATOMIC_ROOT_NAMESPACE_ANCHOR,
            old_value.map(|value| hash_anchor_count_entry(owner_id, value)),
            new_value.map(|value| hash_anchor_count_entry(owner_id, value)),
        );
    }

    fn apply_entry(&mut self, namespace: u8, old_hash: Option<[u8; 32]>, new_hash: Option<[u8; 32]>) {
        if old_hash == new_hash {
            return;
        }
        if let Some(hash) = old_hash {
            let (count, xor) = self.namespace_mut(namespace);
            *count = count.saturating_sub(1);
            xor_hash_in_place(xor, &hash);
        }
        if let Some(hash) = new_hash {
            let (count, xor) = self.namespace_mut(namespace);
            *count = count.saturating_add(1);
            xor_hash_in_place(xor, &hash);
        }
    }

    fn namespace_mut(&mut self, namespace: u8) -> (&mut u64, &mut [u8; 32]) {
        match namespace {
            ATOMIC_ROOT_NAMESPACE_NONCE => (&mut self.nonce_count, &mut self.nonce_xor),
            ATOMIC_ROOT_NAMESPACE_ASSET => (&mut self.asset_count, &mut self.asset_xor),
            ATOMIC_ROOT_NAMESPACE_BALANCE => (&mut self.balance_count, &mut self.balance_xor),
            ATOMIC_ROOT_NAMESPACE_ANCHOR => (&mut self.anchor_count, &mut self.anchor_xor),
            _ => unreachable!("unknown atomic root namespace"),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomicConsensusStateDelta {
    pub nonce_changes: Vec<AtomicNonceChange>,
    pub asset_changes: Vec<AtomicAssetChange>,
    pub balance_changes: Vec<AtomicBalanceChange>,
    pub anchor_count_changes: Vec<AtomicAnchorCountChange>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomicNonceChange {
    pub key: AtomicNonceKey,
    pub old_value: Option<u64>,
    pub new_value: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomicAssetChange {
    pub asset_id: [u8; 32],
    pub old_value: Option<AtomicAssetState>,
    pub new_value: Option<AtomicAssetState>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomicBalanceChange {
    pub key: AtomicBalanceKey,
    pub old_value: Option<u128>,
    pub new_value: Option<u128>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomicAnchorCountChange {
    pub owner_id: [u8; 32],
    pub old_value: Option<u64>,
    pub new_value: Option<u64>,
}

#[derive(Clone, Debug, Default)]
struct AtomicConsensusStateDeltaBuilder {
    nonces: HashMap<AtomicNonceKey, DeltaValue<u64>>,
    assets: HashMap<[u8; 32], DeltaValue<AtomicAssetState>>,
    balances: HashMap<AtomicBalanceKey, DeltaValue<u128>>,
    anchor_counts: HashMap<[u8; 32], DeltaValue<u64>>,
}

#[derive(Clone, Debug)]
struct DeltaValue<T> {
    old_value: Option<T>,
    new_value: Option<T>,
}

fn default_atomic_liquidity_unlocked() -> bool {
    true
}

fn default_atomic_token_version() -> u8 {
    ATOMIC_CURRENT_TOKEN_VERSION
}

fn default_atomic_liquidity_curve_version() -> u8 {
    ATOMIC_CURRENT_LIQUIDITY_CURVE_VERSION
}

fn default_atomic_liquidity_curve_mode() -> u8 {
    ATOMIC_DEFAULT_LIQUIDITY_CURVE_MODE
}

fn record_delta<K, V>(map: &mut HashMap<K, DeltaValue<V>>, key: K, old_value: Option<V>, new_value: Option<V>)
where
    K: Eq + std::hash::Hash,
    V: Clone + Eq,
{
    match map.entry(key) {
        std::collections::hash_map::Entry::Occupied(mut entry) => {
            if old_value == new_value {
                return;
            }
            entry.get_mut().new_value = new_value;
            if entry.get().old_value == entry.get().new_value {
                entry.remove();
            }
        }
        std::collections::hash_map::Entry::Vacant(entry) => {
            if old_value != new_value {
                entry.insert(DeltaValue { old_value, new_value });
            }
        }
    }
}

impl AtomicConsensusStateDeltaBuilder {
    fn record_nonce(&mut self, key: AtomicNonceKey, old_value: Option<u64>, new_value: Option<u64>) {
        record_delta(&mut self.nonces, key, old_value, new_value);
    }

    fn record_asset(&mut self, asset_id: [u8; 32], old_value: Option<AtomicAssetState>, new_value: Option<AtomicAssetState>) {
        record_delta(&mut self.assets, asset_id, old_value, new_value);
    }

    fn record_balance(&mut self, key: AtomicBalanceKey, old_value: Option<u128>, new_value: Option<u128>) {
        record_delta(&mut self.balances, key, old_value, new_value);
    }

    fn record_anchor_count(&mut self, owner_id: [u8; 32], old_value: Option<u64>, new_value: Option<u64>) {
        record_delta(&mut self.anchor_counts, owner_id, old_value, new_value);
    }

    fn into_delta(self) -> AtomicConsensusStateDelta {
        let mut nonce_changes: Vec<_> = self
            .nonces
            .into_iter()
            .map(|(key, value)| AtomicNonceChange { key, old_value: value.old_value, new_value: value.new_value })
            .collect();
        nonce_changes.sort_unstable_by(|a, b| a.key.cmp(&b.key));

        let mut asset_changes: Vec<_> = self
            .assets
            .into_iter()
            .map(|(asset_id, value)| AtomicAssetChange { asset_id, old_value: value.old_value, new_value: value.new_value })
            .collect();
        asset_changes.sort_unstable_by(|a, b| a.asset_id.cmp(&b.asset_id));

        let mut balance_changes: Vec<_> = self
            .balances
            .into_iter()
            .map(|(key, value)| AtomicBalanceChange { key, old_value: value.old_value, new_value: value.new_value })
            .collect();
        balance_changes.sort_unstable_by(|a, b| a.key.cmp(&b.key));

        let mut anchor_count_changes: Vec<_> = self
            .anchor_counts
            .into_iter()
            .map(|(owner_id, value)| AtomicAnchorCountChange { owner_id, old_value: value.old_value, new_value: value.new_value })
            .collect();
        anchor_count_changes.sort_unstable_by(|a, b| a.owner_id.cmp(&b.owner_id));

        AtomicConsensusStateDelta { nonce_changes, asset_changes, balance_changes, anchor_count_changes }
    }
}

impl AtomicConsensusStateDelta {
    pub fn is_empty(&self) -> bool {
        self.nonce_changes.is_empty()
            && self.asset_changes.is_empty()
            && self.balance_changes.is_empty()
            && self.anchor_count_changes.is_empty()
    }

    pub fn change_count(&self) -> usize {
        self.nonce_changes.len() + self.asset_changes.len() + self.balance_changes.len() + self.anchor_count_changes.len()
    }
}

impl AtomicConsensusState {
    pub fn root_only(root_accumulator: AtomicConsensusRootAccumulator) -> Self {
        Self { root_accumulator, ..Self::default() }
    }

    pub fn root_accumulator(&self) -> AtomicConsensusRootAccumulator {
        if self.current_store.is_some()
            || self.next_nonces.is_empty() && self.assets.is_empty() && self.balances.is_empty() && self.anchor_counts.is_empty()
        {
            self.root_accumulator
        } else {
            AtomicConsensusRootAccumulator::from_state_maps(self)
        }
    }

    pub fn root_only_canonical_bytes(state_hash: [u8; 32]) -> Vec<u8> {
        let mut out = Vec::with_capacity(ATOMIC_CONSENSUS_STATE_MAGIC.len() + ATOMIC_CONSENSUS_STATE_ROOT_ONLY_TAG.len() + 32);
        out.extend_from_slice(ATOMIC_CONSENSUS_STATE_MAGIC);
        out.extend_from_slice(ATOMIC_CONSENSUS_STATE_ROOT_ONLY_TAG);
        out.extend_from_slice(&state_hash);
        out
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(ATOMIC_CONSENSUS_STATE_MAGIC);

        let mut nonce_keys = self.next_nonces.keys().copied().collect::<Vec<_>>();
        nonce_keys.sort();
        write_len(&mut out, nonce_keys.len());
        for key in nonce_keys {
            out.extend_from_slice(&key.owner_id);
            out.push(key.scope_kind);
            out.extend_from_slice(&key.scope_id);
            write_u64(&mut out, self.next_nonces[&key]);
        }

        let mut asset_ids = self.assets.keys().copied().collect::<Vec<_>>();
        asset_ids.sort();
        write_len(&mut out, asset_ids.len());
        for asset_id in asset_ids {
            out.extend_from_slice(&asset_id);
            write_atomic_asset(&mut out, &self.assets[&asset_id]);
        }

        let mut balance_keys = self.balances.keys().copied().collect::<Vec<_>>();
        balance_keys.sort();
        write_len(&mut out, balance_keys.len());
        for key in balance_keys {
            out.extend_from_slice(&key.asset_id);
            out.extend_from_slice(&key.owner_id);
            write_u128(&mut out, self.balances[&key]);
        }

        let mut anchor_owner_ids = self.anchor_counts.keys().copied().collect::<Vec<_>>();
        anchor_owner_ids.sort();
        write_len(&mut out, anchor_owner_ids.len());
        for owner_id in anchor_owner_ids {
            out.extend_from_slice(&owner_id);
            write_u64(&mut out, self.anchor_counts[&owner_id]);
        }

        out
    }

    pub fn canonical_hash_from_canonical_bytes(bytes: &[u8]) -> Result<[u8; 32], String> {
        if let Some(state_hash) = decode_root_only_canonical_bytes(bytes)? {
            return Ok(state_hash);
        }
        Ok(Self::try_from_canonical_bytes(bytes)?.canonical_hash())
    }

    pub fn try_from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        if decode_root_only_canonical_bytes(bytes)?.is_some() {
            return Err("root-only Atomic consensus state cannot be imported as a full state".to_string());
        }

        let mut reader = AtomicStateReader::new(bytes);
        reader.read_exact_magic(ATOMIC_CONSENSUS_STATE_MAGIC)?;
        let mut state = Self::default();

        let nonce_count = reader.read_len()?;
        for _ in 0..nonce_count {
            let owner_id = reader.read_hash32()?;
            let scope_kind = reader.read_u8()?;
            let scope_id = reader.read_hash32()?;
            let key = AtomicNonceKey { owner_id, scope_kind, scope_id };
            key.validate()?;
            let value = reader.read_u64()?;
            if state.next_nonces.insert(key, value).is_some() {
                return Err("duplicate atomic nonce key".to_string());
            }
        }

        let asset_count = reader.read_len()?;
        for _ in 0..asset_count {
            let asset_id = reader.read_hash32()?;
            let asset = reader.read_atomic_asset()?;
            if state.assets.insert(asset_id, asset).is_some() {
                return Err("duplicate atomic asset id".to_string());
            }
        }

        let balance_count = reader.read_len()?;
        for _ in 0..balance_count {
            let asset_id = reader.read_hash32()?;
            let owner_id = reader.read_hash32()?;
            let key = AtomicBalanceKey { asset_id, owner_id };
            let value = reader.read_u128()?;
            if state.balances.insert(key, value).is_some() {
                return Err("duplicate atomic balance key".to_string());
            }
        }

        let anchor_count = reader.read_len()?;
        for _ in 0..anchor_count {
            let owner_id = reader.read_hash32()?;
            let value = reader.read_u64()?;
            if state.anchor_counts.insert(owner_id, value).is_some() {
                return Err("duplicate atomic anchor owner id".to_string());
            }
        }

        reader.finish()?;
        state.rebuild_liquidity_vault_outpoint_index();
        state.validate_normalized()?;
        state.root_accumulator = AtomicConsensusRootAccumulator::from_state_maps(&state);
        Ok(state)
    }

    pub fn as_virtual_root_state(&self) -> Self {
        Self::root_only(self.root_accumulator())
    }

    pub fn is_root_only(&self) -> bool {
        !self.has_in_memory_values() && self.root_accumulator != AtomicConsensusRootAccumulator::default()
    }

    pub fn materialized_vault_count(&self) -> Option<usize> {
        (self.current_store.is_none() && !self.is_root_only()).then_some(self.liquidity_vault_outpoints.len())
    }

    fn has_in_memory_values(&self) -> bool {
        !self.next_nonces.is_empty()
            || !self.assets.is_empty()
            || !self.balances.is_empty()
            || !self.anchor_counts.is_empty()
            || !self.liquidity_vault_outpoints.is_empty()
    }

    pub fn attach_current_store(mut self, store: Arc<DbAtomicStateStore>) -> Self {
        self.current_store = Some(store);
        self
    }

    pub(crate) fn is_disk_backed(&self) -> bool {
        self.current_store.is_some()
    }

    pub fn begin_delta_tracking(&mut self) {
        self.delta_tracking = true;
        self.dirty_delta = AtomicConsensusStateDeltaBuilder::default();
    }

    pub fn take_delta(&mut self) -> AtomicConsensusStateDelta {
        self.delta_tracking = false;
        std::mem::take(&mut self.dirty_delta).into_delta()
    }

    pub fn rebuild_liquidity_vault_outpoint_index(&mut self) {
        if self.is_disk_backed() {
            return;
        }
        self.liquidity_vault_outpoints.clear();
        for (asset_id, asset) in self.assets.iter() {
            let Some(pool) = asset.liquidity.as_ref() else {
                continue;
            };
            if !matches!(asset.asset_class, AtomicAssetClass::Liquidity) {
                continue;
            }
            self.liquidity_vault_outpoints.insert(pool.vault_outpoint, *asset_id);
        }
    }

    fn read_store_nonce(&self, key: &AtomicNonceKey) -> Option<u64> {
        self.current_store
            .as_ref()
            .map(|store| {
                store.read_current_nonce(key).unwrap_or_else(|err| panic!("failed reading current Atomic nonce from DB: {err}"))
            })
            .flatten()
    }

    fn read_store_asset(&self, asset_id: &[u8; 32]) -> Option<AtomicAssetState> {
        self.current_store
            .as_ref()
            .map(|store| {
                store.read_current_asset(asset_id).unwrap_or_else(|err| panic!("failed reading current Atomic asset from DB: {err}"))
            })
            .flatten()
    }

    fn read_store_balance(&self, key: &AtomicBalanceKey) -> Option<u128> {
        self.current_store
            .as_ref()
            .map(|store| {
                store.read_current_balance(key).unwrap_or_else(|err| panic!("failed reading current Atomic balance from DB: {err}"))
            })
            .flatten()
    }

    fn read_store_anchor_count(&self, owner_id: &[u8; 32]) -> Option<u64> {
        self.current_store
            .as_ref()
            .map(|store| {
                store
                    .read_current_anchor_count(owner_id)
                    .unwrap_or_else(|err| panic!("failed reading current Atomic anchor count from DB: {err}"))
            })
            .flatten()
    }

    fn nonce_option(&self, key: &AtomicNonceKey) -> Option<u64> {
        if self.deleted_nonces.contains(key) {
            return None;
        }
        self.next_nonces.get(key).copied().or_else(|| self.read_store_nonce(key))
    }

    pub fn has_nonce(&self, key: &AtomicNonceKey) -> bool {
        self.nonce_option(key).is_some()
    }

    pub fn next_nonce(&self, key: &AtomicNonceKey) -> u64 {
        self.nonce_option(key).unwrap_or(1)
    }

    pub fn set_next_nonce(&mut self, key: AtomicNonceKey, nonce: u64) {
        let old_value = self.nonce_option(&key);
        if self.delta_tracking {
            self.dirty_delta.record_nonce(key, old_value, Some(nonce));
        }
        self.set_nonce_value_without_delta(key, Some(nonce));
    }

    fn set_nonce_value_without_delta(&mut self, key: AtomicNonceKey, value: Option<u64>) {
        let old_value = self.nonce_option(&key);
        if self.is_disk_backed() {
            self.root_accumulator.apply_nonce(&key, old_value, value);
        }
        match value {
            Some(nonce) => {
                self.deleted_nonces.remove(&key);
                self.next_nonces.insert(key, nonce);
            }
            None => {
                self.next_nonces.remove(&key);
                if self.is_disk_backed() {
                    self.deleted_nonces.insert(key);
                }
            }
        }
    }

    fn asset_option(&self, asset_id: &[u8; 32]) -> Option<AtomicAssetState> {
        if self.deleted_assets.contains(asset_id) {
            return None;
        }
        self.assets.get(asset_id).cloned().or_else(|| self.read_store_asset(asset_id))
    }

    fn balance_option(&self, key: &AtomicBalanceKey) -> Option<u128> {
        if self.deleted_balances.contains(key) {
            return None;
        }
        self.balances.get(key).copied().or_else(|| self.read_store_balance(key))
    }

    fn anchor_count_option(&self, owner_id: &[u8; 32]) -> Option<u64> {
        if self.deleted_anchor_counts.contains(owner_id) {
            return None;
        }
        self.anchor_counts.get(owner_id).copied().or_else(|| self.read_store_anchor_count(owner_id))
    }

    fn store_vault_asset(&self, outpoint: TransactionOutpoint) -> Option<[u8; 32]> {
        self.current_store
            .as_ref()
            .map(|store| {
                store
                    .read_current_vault_asset(outpoint)
                    .unwrap_or_else(|err| panic!("failed reading current Atomic liquidity vault index from DB: {err}"))
            })
            .flatten()
    }

    fn set_vault_index_for_asset_change(
        &mut self,
        asset_id: [u8; 32],
        old_value: Option<&AtomicAssetState>,
        new_value: Option<&AtomicAssetState>,
    ) -> Result<(), String> {
        if let Some(previous_asset) = old_value {
            if let Some(previous_pool) = previous_asset.liquidity.as_ref() {
                self.liquidity_vault_outpoints.remove(&previous_pool.vault_outpoint);
                if self.is_disk_backed() {
                    self.deleted_vault_outpoints.insert(previous_pool.vault_outpoint);
                }
            }
        }

        let Some(asset) = new_value else {
            return Ok(());
        };

        if matches!(asset.asset_class, AtomicAssetClass::Liquidity) {
            let pool = asset
                .liquidity
                .as_ref()
                .ok_or_else(|| format!("liquidity state missing for asset `{}`", faster_hex::hex_string(&asset_id)))?;
            self.deleted_vault_outpoints.remove(&pool.vault_outpoint);
            if let Some(previous_asset_id) = self.liquidity_vault_outpoints.insert(pool.vault_outpoint, asset_id) {
                if previous_asset_id != asset_id {
                    return Err(format!("multiple liquidity assets share vault outpoint `{}`", pool.vault_outpoint));
                }
            }
        }
        Ok(())
    }

    fn set_asset_value_without_delta(&mut self, asset_id: [u8; 32], asset: Option<AtomicAssetState>) -> Result<(), String> {
        let old_value = self.asset_option(&asset_id);
        if self.is_disk_backed() {
            self.root_accumulator.apply_asset(&asset_id, old_value.as_ref(), asset.as_ref());
        }
        self.set_vault_index_for_asset_change(asset_id, old_value.as_ref(), asset.as_ref())?;
        match asset {
            Some(asset) => {
                self.deleted_assets.remove(&asset_id);
                self.assets.insert(asset_id, asset);
            }
            None => {
                self.assets.remove(&asset_id);
                if self.is_disk_backed() {
                    self.deleted_assets.insert(asset_id);
                }
            }
        }
        Ok(())
    }

    fn set_balance_value_without_delta(&mut self, key: AtomicBalanceKey, value: Option<u128>) {
        let old_value = self.balance_option(&key);
        if self.is_disk_backed() {
            self.root_accumulator.apply_balance(&key, old_value, value);
        }
        match value {
            Some(amount) => {
                self.deleted_balances.remove(&key);
                self.balances.insert(key, amount);
            }
            None => {
                self.balances.remove(&key);
                if self.is_disk_backed() {
                    self.deleted_balances.insert(key);
                }
            }
        }
    }

    fn set_anchor_count_value_without_delta(&mut self, owner_id: [u8; 32], value: Option<u64>) {
        let old_value = self.anchor_count_option(&owner_id);
        if self.is_disk_backed() {
            self.root_accumulator.apply_anchor_count(&owner_id, old_value, value);
        }
        match value {
            Some(count) => {
                self.deleted_anchor_counts.remove(&owner_id);
                self.anchor_counts.insert(owner_id, count);
            }
            None => {
                self.anchor_counts.remove(&owner_id);
                if self.is_disk_backed() {
                    self.deleted_anchor_counts.insert(owner_id);
                }
            }
        }
    }

    pub fn has_asset(&self, asset_id: &[u8; 32]) -> bool {
        self.asset_option(asset_id).is_some()
    }

    pub fn asset(&self, asset_id: &[u8; 32]) -> Option<&AtomicAssetState> {
        self.assets.get(asset_id)
    }

    pub fn cloned_asset(&self, asset_id: &[u8; 32]) -> Option<AtomicAssetState> {
        self.asset_option(asset_id)
    }

    pub fn pool_nonce(&self, asset_id: &[u8; 32]) -> u64 {
        self.cloned_asset(asset_id).and_then(|asset| asset.liquidity.map(|pool| pool.pool_nonce)).unwrap_or(1)
    }

    pub fn set_asset(&mut self, asset_id: [u8; 32], asset: AtomicAssetState) -> Result<(), String> {
        let old_value = self.asset_option(&asset_id);
        if self.delta_tracking {
            self.dirty_delta.record_asset(asset_id, old_value.clone(), Some(asset.clone()));
        }
        self.set_asset_value_without_delta(asset_id, Some(asset))
    }

    pub fn has_balance(&self, key: &AtomicBalanceKey) -> bool {
        self.balance_option(key).is_some()
    }

    pub fn balance(&self, key: &AtomicBalanceKey) -> u128 {
        self.balance_option(key).unwrap_or(0)
    }

    pub fn set_balance(&mut self, key: AtomicBalanceKey, amount: u128) {
        let old_value = self.balance_option(&key);
        let new_value = (amount != 0).then_some(amount);
        if self.delta_tracking {
            self.dirty_delta.record_balance(key, old_value, new_value);
        }
        self.set_balance_value_without_delta(key, new_value);
    }

    pub fn has_anchor_count(&self, owner_id: &[u8; 32]) -> bool {
        self.anchor_count_option(owner_id).is_some()
    }

    pub fn anchor_count(&self, owner_id: &[u8; 32]) -> u64 {
        self.anchor_count_option(owner_id).unwrap_or(0)
    }

    pub fn set_anchor_count(&mut self, owner_id: [u8; 32], count: u64) {
        let old_value = self.anchor_count_option(&owner_id);
        let new_value = (count != 0).then_some(count);
        if self.delta_tracking {
            self.dirty_delta.record_anchor_count(owner_id, old_value, new_value);
        }
        self.set_anchor_count_value_without_delta(owner_id, new_value);
    }

    fn apply_delta_value<T>(map: &mut HashMap<T, u64>, key: T, value: Option<u64>)
    where
        T: Eq + std::hash::Hash,
    {
        match value {
            Some(value) => {
                map.insert(key, value);
            }
            None => {
                map.remove(&key);
            }
        }
    }

    pub fn apply_delta_forward(&mut self, delta: &AtomicConsensusStateDelta) -> Result<(), String> {
        self.apply_delta(delta, true)
    }

    pub fn apply_delta_rollback(&mut self, delta: &AtomicConsensusStateDelta) -> Result<(), String> {
        self.apply_delta(delta, false)
    }

    fn apply_delta(&mut self, delta: &AtomicConsensusStateDelta, forward: bool) -> Result<(), String> {
        let delta_tracking = self.delta_tracking;
        self.delta_tracking = false;

        for change in &delta.nonce_changes {
            let value = if forward { change.new_value } else { change.old_value };
            self.set_nonce_value_without_delta(change.key, value);
        }

        for change in &delta.asset_changes {
            let value = if forward { change.new_value.clone() } else { change.old_value.clone() };
            self.set_asset_value_without_delta(change.asset_id, value)?;
        }

        for change in &delta.balance_changes {
            let value = if forward { change.new_value } else { change.old_value };
            self.set_balance_value_without_delta(change.key, value);
        }

        for change in &delta.anchor_count_changes {
            let value = if forward { change.new_value } else { change.old_value };
            self.set_anchor_count_value_without_delta(change.owner_id, value);
        }

        self.delta_tracking = delta_tracking;
        if delta_tracking {
            self.dirty_delta = AtomicConsensusStateDeltaBuilder::default();
        }
        Ok(())
    }

    pub fn liquidity_asset_by_vault_outpoint(&self, outpoint: TransactionOutpoint) -> Result<Option<[u8; 32]>, String> {
        if let Some(asset_id) = self.liquidity_vault_outpoints.get(&outpoint).copied() {
            let asset = self
                .cloned_asset(&asset_id)
                .ok_or_else(|| format!("liquidity vault index references missing asset `{}`", faster_hex::hex_string(&asset_id)))?;
            let pool = asset.liquidity.as_ref().ok_or_else(|| {
                format!("liquidity vault index references asset `{}` without liquidity state", faster_hex::hex_string(&asset_id))
            })?;
            if !matches!(asset.asset_class, AtomicAssetClass::Liquidity) || pool.vault_outpoint != outpoint {
                return Err(format!("liquidity vault index mismatch for outpoint `{}`", outpoint));
            }
            return Ok(Some(asset_id));
        }

        if self.deleted_vault_outpoints.contains(&outpoint) {
            return Ok(None);
        }
        if let Some(asset_id) = self.store_vault_asset(outpoint) {
            let asset = self
                .cloned_asset(&asset_id)
                .ok_or_else(|| format!("liquidity vault index references missing asset `{}`", faster_hex::hex_string(&asset_id)))?;
            let pool = asset.liquidity.as_ref().ok_or_else(|| {
                format!("liquidity vault index references asset `{}` without liquidity state", faster_hex::hex_string(&asset_id))
            })?;
            if !matches!(asset.asset_class, AtomicAssetClass::Liquidity) || pool.vault_outpoint != outpoint {
                return Err(format!("liquidity vault index mismatch for outpoint `{}`", outpoint));
            }
            return Ok(Some(asset_id));
        }

        let mut matched = None;
        for (asset_id, asset) in self.assets.iter() {
            let Some(pool) = asset.liquidity.as_ref() else {
                continue;
            };
            if !matches!(asset.asset_class, AtomicAssetClass::Liquidity) || pool.vault_outpoint != outpoint {
                continue;
            }
            if matched.replace(*asset_id).is_some() {
                return Err(format!("multiple liquidity assets share vault outpoint `{}`", outpoint));
            }
        }
        Ok(matched)
    }

    pub fn canonical_hash(&self) -> [u8; 32] {
        self.root_accumulator().hash()
    }

    pub fn p2p_token_audit_hash(&self) -> Option<[u8; 32]> {
        if self.is_root_only() || self.is_disk_backed() {
            return None;
        }
        Some(compute_p2p_token_audit_hash(self))
    }

    pub fn header_commitment(utxo_commitment: Hash, atomic_state_hash: [u8; 32], payload_hf_active: bool) -> Hash {
        if !payload_hf_active {
            return utxo_commitment;
        }

        let mut hasher = Blake2bParams::new().hash_length(32).to_state();
        hasher.update(ATOMIC_STATE_COMMITMENT_DOMAIN);
        hasher.update(&utxo_commitment.as_bytes());
        hasher.update(&atomic_state_hash);
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_bytes());
        Hash::from_bytes(out)
    }

    pub fn header_commitment_for_state(&self, utxo_commitment: Hash, payload_hf_active: bool) -> Hash {
        Self::header_commitment(utxo_commitment, self.canonical_hash(), payload_hf_active)
    }

    pub fn validate_normalized(&self) -> Result<(), String> {
        for (key, nonce) in self.next_nonces.iter() {
            key.validate()?;
            if *nonce < 2 {
                return Err(format!(
                    "atomic nonce for owner `{}` scope `{}` `{}` is not normalized",
                    faster_hex::hex_string(&key.owner_id),
                    key.scope_kind,
                    faster_hex::hex_string(&key.scope_id)
                ));
            }
        }

        for (owner_id, count) in self.anchor_counts.iter() {
            if *count == 0 {
                return Err(format!("zero atomic anchor count for owner `{}`", faster_hex::hex_string(owner_id)));
            }
        }

        let mut balance_totals: HashMap<[u8; 32], u128> = HashMap::new();
        for (key, amount) in self.balances.iter() {
            if *amount == 0 {
                return Err(format!(
                    "zero atomic balance for asset `{}` owner `{}`",
                    faster_hex::hex_string(&key.asset_id),
                    faster_hex::hex_string(&key.owner_id)
                ));
            }
            if !self.assets.contains_key(&key.asset_id) {
                return Err(format!("atomic balance references unknown asset `{}`", faster_hex::hex_string(&key.asset_id)));
            }
            let total = balance_totals.entry(key.asset_id).or_insert(0);
            *total = total
                .checked_add(*amount)
                .ok_or_else(|| format!("balance total overflow for asset `{}`", faster_hex::hex_string(&key.asset_id)))?;
        }

        let mut expected_vault_index = HashMap::new();
        for (asset_id, asset) in self.assets.iter() {
            validate_token_version(asset.token_version)?;
            if asset.decimals > MAX_ATOMIC_DECIMALS {
                return Err(format!(
                    "atomic asset `{}` decimals `{}` above max `{}`",
                    faster_hex::hex_string(asset_id),
                    asset.decimals,
                    MAX_ATOMIC_DECIMALS
                ));
            }
            if asset.name.len() > MAX_ATOMIC_NAME_LEN {
                return Err(format!("atomic asset `{}` name exceeds max length", faster_hex::hex_string(asset_id)));
            }
            if asset.symbol.len() > MAX_ATOMIC_SYMBOL_LEN {
                return Err(format!("atomic asset `{}` symbol exceeds max length", faster_hex::hex_string(asset_id)));
            }
            if asset.metadata.len() > MAX_ATOMIC_METADATA_LEN {
                return Err(format!("atomic asset `{}` metadata exceeds max length", faster_hex::hex_string(asset_id)));
            }
            if std::str::from_utf8(&asset.name).is_err() || std::str::from_utf8(&asset.symbol).is_err() {
                return Err(format!("atomic asset `{}` name/symbol must be valid utf-8", faster_hex::hex_string(asset_id)));
            }
            let created_flags = [asset.created_block_hash.is_some(), asset.created_daa_score.is_some(), asset.created_at.is_some()];
            if created_flags.iter().any(|present| *present) && created_flags.iter().any(|present| !*present) {
                return Err(format!("atomic asset `{}` has partial creation metadata", faster_hex::hex_string(asset_id)));
            }
            if asset.platform_tag.len() > MAX_ATOMIC_PLATFORM_TAG_LEN {
                return Err(format!("atomic asset `{}` platform tag exceeds max length", faster_hex::hex_string(asset_id)));
            }
            if std::str::from_utf8(&asset.platform_tag).is_err() {
                return Err(format!("atomic asset `{}` platform tag is not valid utf-8", faster_hex::hex_string(asset_id)));
            }
            match asset.supply_mode {
                AtomicSupplyMode::Uncapped if asset.max_supply != 0 => {
                    return Err(format!("uncapped asset `{}` has non-zero max_supply", faster_hex::hex_string(asset_id)))
                }
                AtomicSupplyMode::Capped if asset.max_supply == 0 => {
                    return Err(format!("capped asset `{}` has zero max_supply", faster_hex::hex_string(asset_id)))
                }
                AtomicSupplyMode::Capped if asset.total_supply > asset.max_supply => {
                    return Err(format!("asset `{}` total_supply exceeds max_supply", faster_hex::hex_string(asset_id)))
                }
                _ => {}
            }

            let balance_total = balance_totals.get(asset_id).copied().unwrap_or(0);
            if balance_total != asset.total_supply {
                return Err(format!(
                    "asset `{}` balance total `{}` does not match total_supply `{}`",
                    faster_hex::hex_string(asset_id),
                    balance_total,
                    asset.total_supply
                ));
            }

            match asset.asset_class {
                AtomicAssetClass::Standard => {
                    if asset.liquidity.is_some() {
                        return Err(format!("standard asset `{}` has liquidity state", faster_hex::hex_string(asset_id)));
                    }
                }
                AtomicAssetClass::Liquidity => {
                    if asset.decimals != 0 {
                        return Err(format!("liquidity asset `{}` has non-zero decimals", faster_hex::hex_string(asset_id)));
                    }
                    validate_liquidity_asset_normalized(*asset_id, asset, &mut expected_vault_index)?;
                }
            }
        }

        if self.liquidity_vault_outpoints != expected_vault_index {
            return Err("liquidity vault outpoint index is not normalized".to_string());
        }

        Ok(())
    }
}

fn validate_liquidity_asset_normalized(
    asset_id: [u8; 32],
    asset: &AtomicAssetState,
    expected_vault_index: &mut HashMap<TransactionOutpoint, [u8; 32]>,
) -> Result<(), String> {
    let pool = asset
        .liquidity
        .as_ref()
        .ok_or_else(|| format!("liquidity asset `{}` is missing pool state", faster_hex::hex_string(&asset_id)))?;
    if asset.mint_authority_owner_id != [0u8; 32] {
        return Err(format!("liquidity asset `{}` has non-zero mint authority", faster_hex::hex_string(&asset_id)));
    }
    if !matches!(asset.supply_mode, AtomicSupplyMode::Capped) {
        return Err(format!("liquidity asset `{}` is not capped", faster_hex::hex_string(&asset_id)));
    }
    if pool.pool_nonce == 0 {
        return Err(format!("liquidity asset `{}` has zero pool nonce", faster_hex::hex_string(&asset_id)));
    }
    validate_liquidity_curve_version(pool.curve_version)?;
    validate_liquidity_curve_mode(pool.curve_mode)?;
    validate_liquidity_curve_parameters(
        pool.curve_mode,
        pool.individual_virtual_cpay_reserves_sompi,
        pool.individual_virtual_token_multiplier_bps,
    )?;
    if pool.unlock_target_sompi == 0 && !pool.unlocked {
        return Err(format!("liquidity asset `{}` has disabled lock but is not marked unlocked", faster_hex::hex_string(&asset_id)));
    }
    if pool.unlock_target_sompi > MAX_SOMPI {
        return Err(format!("liquidity asset `{}` unlock target exceeds MAX_SOMPI", faster_hex::hex_string(&asset_id)));
    }
    if pool.unlock_target_sompi > 0 && !pool.unlocked && pool.real_cpay_reserves_sompi >= pool.unlock_target_sompi {
        return Err(format!(
            "liquidity asset `{}` reached unlock target but is not marked unlocked",
            faster_hex::hex_string(&asset_id)
        ));
    }
    if pool.real_cpay_reserves_sompi == 0 {
        return Err(format!("liquidity asset `{}` has zero real CPAY reserve", faster_hex::hex_string(&asset_id)));
    }
    if pool.real_token_reserves == 0 {
        return Err(format!("liquidity asset `{}` has zero real token reserve", faster_hex::hex_string(&asset_id)));
    }
    if pool.virtual_cpay_reserves_sompi == 0 || pool.virtual_token_reserves == 0 {
        return Err(format!("liquidity asset `{}` has zero virtual reserve", faster_hex::hex_string(&asset_id)));
    }

    let expected_vault_value = pool
        .real_cpay_reserves_sompi
        .checked_add(pool.unclaimed_fee_total_sompi)
        .ok_or_else(|| format!("liquidity asset `{}` vault value overflow", faster_hex::hex_string(&asset_id)))?;
    if pool.vault_value_sompi != expected_vault_value {
        return Err(format!("liquidity asset `{}` vault value invariant violation", faster_hex::hex_string(&asset_id)));
    }

    let expected_supply = asset
        .total_supply
        .checked_add(pool.real_token_reserves)
        .ok_or_else(|| format!("liquidity asset `{}` supply invariant overflow", faster_hex::hex_string(&asset_id)))?;
    if expected_supply != asset.max_supply {
        return Err(format!("liquidity asset `{}` supply invariant violation", faster_hex::hex_string(&asset_id)));
    }

    validate_fee_recipients_normalized(asset_id, pool)?;

    if let Some(previous_asset_id) = expected_vault_index.insert(pool.vault_outpoint, asset_id) {
        if previous_asset_id != asset_id {
            return Err(format!("multiple liquidity assets share vault outpoint `{}`", pool.vault_outpoint));
        }
    }

    Ok(())
}

fn validate_fee_recipients_normalized(asset_id: [u8; 32], pool: &AtomicLiquidityPoolState) -> Result<(), String> {
    match pool.fee_bps {
        0 if !pool.fee_recipients.is_empty() => {
            return Err(format!("liquidity asset `{}` has recipients with zero fee_bps", faster_hex::hex_string(&asset_id)))
        }
        0 => {}
        MIN_ATOMIC_LIQUIDITY_FEE_BPS..=MAX_ATOMIC_LIQUIDITY_FEE_BPS => {
            if pool.fee_recipients.is_empty() || pool.fee_recipients.len() > MAX_ATOMIC_LIQUIDITY_FEE_RECIPIENTS {
                return Err(format!("liquidity asset `{}` has invalid fee recipient count", faster_hex::hex_string(&asset_id)));
            }
        }
        _ => return Err(format!("liquidity asset `{}` has invalid fee_bps", faster_hex::hex_string(&asset_id))),
    }

    let mut unclaimed_sum = 0u64;
    let mut previous_order_key: Option<(u8, &[u8])> = None;
    for recipient in pool.fee_recipients.iter() {
        let owner_id = atomic_owner_id_from_address_components(recipient.address_version, &recipient.address_payload)
            .ok_or_else(|| format!("liquidity asset `{}` has invalid fee recipient address", faster_hex::hex_string(&asset_id)))?;
        if owner_id != recipient.owner_id {
            return Err(format!("liquidity asset `{}` fee recipient owner mismatch", faster_hex::hex_string(&asset_id)));
        }

        let order_key = (recipient.address_version, recipient.address_payload.as_slice());
        if previous_order_key.is_some_and(|previous| previous >= order_key) {
            return Err(format!(
                "liquidity asset `{}` fee recipients are duplicated or not canonically sorted",
                faster_hex::hex_string(&asset_id)
            ));
        }
        previous_order_key = Some(order_key);

        unclaimed_sum = unclaimed_sum
            .checked_add(recipient.unclaimed_sompi)
            .ok_or_else(|| format!("liquidity asset `{}` fee recipient total overflow", faster_hex::hex_string(&asset_id)))?;
    }
    if unclaimed_sum != pool.unclaimed_fee_total_sompi {
        return Err(format!("liquidity asset `{}` fee total invariant violation", faster_hex::hex_string(&asset_id)));
    }

    Ok(())
}

fn validate_token_version(version: u8) -> Result<(), String> {
    if (1..=ATOMIC_MAX_TOKEN_VERSION).contains(&version) && version == ATOMIC_CURRENT_TOKEN_VERSION {
        Ok(())
    } else {
        Err(format!("unsupported atomic token version `{version}`"))
    }
}

fn validate_liquidity_curve_version(version: u8) -> Result<(), String> {
    if (1..=ATOMIC_MAX_LIQUIDITY_CURVE_VERSION).contains(&version) && version == ATOMIC_CURRENT_LIQUIDITY_CURVE_VERSION {
        Ok(())
    } else {
        Err(format!("unsupported atomic liquidity curve version `{version}`"))
    }
}

fn validate_liquidity_curve_mode(mode: u8) -> Result<(), String> {
    match mode {
        ATOMIC_LIQUIDITY_CURVE_MODE_BASIC | ATOMIC_LIQUIDITY_CURVE_MODE_AGGRESSIVE | ATOMIC_LIQUIDITY_CURVE_MODE_INDIVIDUAL => Ok(()),
        _ => Err(format!("unsupported atomic liquidity curve mode `{mode}`")),
    }
}

fn validate_individual_liquidity_curve_params(
    virtual_cpay_reserves_sompi: u64,
    virtual_token_multiplier_bps: u16,
) -> Result<(), String> {
    if !(ATOMIC_INDIVIDUAL_MIN_VIRTUAL_CPAY_RESERVES_SOMPI..=ATOMIC_INDIVIDUAL_MAX_VIRTUAL_CPAY_RESERVES_SOMPI)
        .contains(&virtual_cpay_reserves_sompi)
    {
        return Err(format!("individual liquidity fixed CPAY `{virtual_cpay_reserves_sompi}` is outside allowed range"));
    }
    if virtual_cpay_reserves_sompi % ATOMIC_INDIVIDUAL_VIRTUAL_CPAY_STEP_SOMPI != 0 {
        return Err(format!("individual liquidity fixed CPAY `{virtual_cpay_reserves_sompi}` is not on the allowed step"));
    }
    if !(ATOMIC_INDIVIDUAL_MIN_VIRTUAL_TOKEN_MULTIPLIER_BPS..=ATOMIC_INDIVIDUAL_MAX_VIRTUAL_TOKEN_MULTIPLIER_BPS)
        .contains(&virtual_token_multiplier_bps)
    {
        return Err(format!("individual liquidity multiplier `{virtual_token_multiplier_bps}` is outside allowed range"));
    }
    if virtual_token_multiplier_bps % ATOMIC_INDIVIDUAL_VIRTUAL_TOKEN_MULTIPLIER_STEP_BPS != 0 {
        return Err(format!("individual liquidity multiplier `{virtual_token_multiplier_bps}` is not on the allowed step"));
    }
    Ok(())
}

fn validate_liquidity_curve_parameters(
    mode: u8,
    individual_virtual_cpay_reserves_sompi: u64,
    individual_virtual_token_multiplier_bps: u16,
) -> Result<(), String> {
    match mode {
        ATOMIC_LIQUIDITY_CURVE_MODE_BASIC | ATOMIC_LIQUIDITY_CURVE_MODE_AGGRESSIVE => {
            if individual_virtual_cpay_reserves_sompi == 0 && individual_virtual_token_multiplier_bps == 0 {
                Ok(())
            } else {
                Err("non-individual liquidity curve must not encode individual parameters".to_string())
            }
        }
        ATOMIC_LIQUIDITY_CURVE_MODE_INDIVIDUAL => {
            validate_individual_liquidity_curve_params(individual_virtual_cpay_reserves_sompi, individual_virtual_token_multiplier_bps)
        }
        _ => Err(format!("unsupported atomic liquidity curve mode `{mode}`")),
    }
}

fn atomic_owner_id_from_address_components(address_version: u8, address_payload: &[u8]) -> Option<[u8; 32]> {
    let auth_scheme = match address_version {
        0 if address_payload.len() == 32 => OWNER_AUTH_SCHEME_PUBKEY,
        1 if address_payload.len() == 33 => OWNER_AUTH_SCHEME_PUBKEY_ECDSA,
        8 if address_payload.len() == 32 => OWNER_AUTH_SCHEME_SCRIPT_HASH,
        _ => return None,
    };
    let pubkey_len = u16::try_from(address_payload.len()).ok()?;
    let mut hasher = Blake2bParams::new().hash_length(32).to_state();
    hasher.update(ATOMIC_OWNER_DOMAIN);
    hasher.update(&[auth_scheme]);
    hasher.update(&pubkey_len.to_le_bytes());
    hasher.update(address_payload);
    let hash = hasher.finalize();
    let mut owner_id = [0u8; 32];
    owner_id.copy_from_slice(hash.as_bytes());
    Some(owner_id)
}

fn xor_hash_in_place(target: &mut [u8; 32], hash: &[u8; 32]) {
    for (target, value) in target.iter_mut().zip(hash.iter()) {
        *target ^= *value;
    }
}

fn finalize_entry_hash(hasher: blake2b_simd::State) -> [u8; 32] {
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_bytes());
    out
}

fn new_entry_hasher(namespace: u8) -> blake2b_simd::State {
    let mut hasher = Blake2bParams::new().hash_length(32).to_state();
    hasher.update(ATOMIC_CONSENSUS_STATE_HASH_DOMAIN);
    hash_u8(&mut hasher, namespace);
    hasher
}

fn hash_nonce_entry(key: &AtomicNonceKey, nonce: u64) -> [u8; 32] {
    let mut hasher = new_entry_hasher(ATOMIC_ROOT_NAMESPACE_NONCE);
    hasher.update(&key.owner_id);
    hash_u8(&mut hasher, key.scope_kind);
    hasher.update(&key.scope_id);
    hash_u64(&mut hasher, nonce);
    finalize_entry_hash(hasher)
}

fn hash_asset_entry(asset_id: &[u8; 32], asset: &AtomicAssetState) -> [u8; 32] {
    let mut hasher = new_entry_hasher(ATOMIC_ROOT_NAMESPACE_ASSET);
    hasher.update(asset_id);
    hash_asset(&mut hasher, asset);
    finalize_entry_hash(hasher)
}

fn hash_balance_entry(key: &AtomicBalanceKey, amount: u128) -> [u8; 32] {
    let mut hasher = new_entry_hasher(ATOMIC_ROOT_NAMESPACE_BALANCE);
    hasher.update(&key.asset_id);
    hasher.update(&key.owner_id);
    hash_u128(&mut hasher, amount);
    finalize_entry_hash(hasher)
}

fn hash_anchor_count_entry(owner_id: &[u8; 32], count: u64) -> [u8; 32] {
    let mut hasher = new_entry_hasher(ATOMIC_ROOT_NAMESPACE_ANCHOR);
    hasher.update(owner_id);
    hash_u64(&mut hasher, count);
    finalize_entry_hash(hasher)
}

fn hash_len(hasher: &mut blake2b_simd::State, len: usize) {
    hash_u64(hasher, len as u64);
}

fn hash_u8(hasher: &mut blake2b_simd::State, value: u8) {
    hasher.update(&[value]);
}

fn hash_u16(hasher: &mut blake2b_simd::State, value: u16) {
    hasher.update(&value.to_le_bytes());
}

fn hash_u32(hasher: &mut blake2b_simd::State, value: u32) {
    hasher.update(&value.to_le_bytes());
}

fn hash_u64(hasher: &mut blake2b_simd::State, value: u64) {
    hasher.update(&value.to_le_bytes());
}

fn hash_u128(hasher: &mut blake2b_simd::State, value: u128) {
    hasher.update(&value.to_le_bytes());
}

fn hash_optional_hash(hasher: &mut blake2b_simd::State, value: &Option<[u8; 32]>) {
    match value {
        Some(hash) => {
            hash_u8(hasher, 1);
            hasher.update(hash);
        }
        None => hash_u8(hasher, 0),
    }
}

fn hash_optional_u64(hasher: &mut blake2b_simd::State, value: Option<u64>) {
    match value {
        Some(value) => {
            hash_u8(hasher, 1);
            hash_u64(hasher, value);
        }
        None => hash_u8(hasher, 0),
    }
}

fn hash_asset(hasher: &mut blake2b_simd::State, asset: &AtomicAssetState) {
    hash_u8(hasher, atomic_asset_class_to_u8(asset.asset_class));
    hash_u8(hasher, asset.token_version);
    hasher.update(&asset.mint_authority_owner_id);
    hash_u8(hasher, atomic_supply_mode_to_u8(asset.supply_mode));
    hash_u128(hasher, asset.max_supply);
    hash_u128(hasher, asset.total_supply);
    hash_len(hasher, asset.platform_tag.len());
    hasher.update(&asset.platform_tag);
    match asset.liquidity.as_ref() {
        Some(pool) => {
            hash_u8(hasher, 1);
            hash_liquidity_pool(hasher, pool);
        }
        None => hash_u8(hasher, 0),
    }
}

fn hash_liquidity_pool(hasher: &mut blake2b_simd::State, pool: &AtomicLiquidityPoolState) {
    hash_u64(hasher, pool.pool_nonce);
    hash_u8(hasher, pool.curve_version);
    hash_u8(hasher, pool.curve_mode);
    hash_u64(hasher, pool.individual_virtual_cpay_reserves_sompi);
    hash_u16(hasher, pool.individual_virtual_token_multiplier_bps);
    hash_u64(hasher, pool.real_cpay_reserves_sompi);
    hash_u128(hasher, pool.real_token_reserves);
    hash_u64(hasher, pool.virtual_cpay_reserves_sompi);
    hash_u128(hasher, pool.virtual_token_reserves);
    hash_u64(hasher, pool.unclaimed_fee_total_sompi);
    hash_u16(hasher, pool.fee_bps);
    hash_len(hasher, pool.fee_recipients.len());
    for recipient in pool.fee_recipients.iter() {
        hasher.update(&recipient.owner_id);
        hash_u8(hasher, recipient.address_version);
        hash_len(hasher, recipient.address_payload.len());
        hasher.update(&recipient.address_payload);
        hash_u64(hasher, recipient.unclaimed_sompi);
    }
    hash_outpoint(hasher, pool.vault_outpoint);
    hash_u64(hasher, pool.vault_value_sompi);
    hash_u64(hasher, pool.unlock_target_sompi);
    hash_u8(hasher, u8::from(pool.unlocked));
}

fn hash_outpoint(hasher: &mut blake2b_simd::State, outpoint: TransactionOutpoint) {
    hasher.update(&outpoint.transaction_id.as_bytes());
    hash_u32(hasher, outpoint.index);
}

fn compute_p2p_token_audit_hash(state: &AtomicConsensusState) -> [u8; 32] {
    let mut buckets = [[0u8; 32]; ATOMIC_P2P_ROOT_BUCKETS];

    let mut asset_ids = state.assets.keys().copied().collect::<Vec<_>>();
    asset_ids.sort_unstable();
    for asset_id in asset_ids {
        if let Some(asset) = state.assets.get(&asset_id) {
            apply_p2p_root_leaf(&mut buckets, &p2p_logical_asset_key(&asset_id), &p2p_asset_value(&asset_id, asset));
        }
    }

    let mut balance_keys = state.balances.keys().copied().collect::<Vec<_>>();
    balance_keys.sort_unstable();
    for key in balance_keys {
        if let Some(amount) = state.balances.get(&key).copied().filter(|amount| *amount > 0) {
            apply_p2p_root_leaf(&mut buckets, &p2p_logical_balance_key(&key), &amount.to_le_bytes());
        }
    }

    let mut nonce_keys = state.next_nonces.keys().copied().collect::<Vec<_>>();
    nonce_keys.sort_unstable();
    for key in nonce_keys {
        if let Some(nonce) = state.next_nonces.get(&key).copied().filter(|nonce| *nonce != 1) {
            apply_p2p_root_leaf(&mut buckets, &p2p_logical_nonce_key(&key), &nonce.to_le_bytes());
        }
    }

    p2p_root_from_buckets(&buckets)
}

fn p2p_logical_asset_key(asset_id: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(33);
    key.push(ATOMIC_P2P_LOGICAL_ASSET);
    key.extend_from_slice(asset_id);
    key
}

fn p2p_logical_balance_key(key: &AtomicBalanceKey) -> Vec<u8> {
    let mut logical = Vec::with_capacity(65);
    logical.push(ATOMIC_P2P_LOGICAL_BALANCE);
    logical.extend_from_slice(&key.asset_id);
    logical.extend_from_slice(&key.owner_id);
    logical
}

fn p2p_logical_nonce_key(key: &AtomicNonceKey) -> Vec<u8> {
    let mut logical = Vec::with_capacity(66);
    logical.push(ATOMIC_P2P_LOGICAL_NONCE);
    logical.extend_from_slice(&key.owner_id);
    logical.push(key.scope_kind);
    logical.extend_from_slice(&key.scope_id);
    logical
}

fn p2p_asset_value(asset_id: &[u8; 32], asset: &AtomicAssetState) -> Vec<u8> {
    let mut out = Vec::with_capacity(192 + asset.platform_tag.len());
    out.extend_from_slice(ATOMIC_P2P_ASSET_ROOT_V1);
    out.extend_from_slice(asset_id);
    out.push(atomic_asset_class_to_u8(asset.asset_class));
    out.push(asset.token_version);
    out.extend_from_slice(&asset.mint_authority_owner_id);
    out.push(atomic_supply_mode_to_u8(asset.supply_mode));
    out.extend_from_slice(&asset.max_supply.to_le_bytes());
    out.extend_from_slice(&asset.total_supply.to_le_bytes());
    p2p_push_bytes(&mut out, &asset.platform_tag);
    match asset.liquidity.as_ref() {
        Some(pool) => {
            out.push(1);
            p2p_append_liquidity(&mut out, pool);
        }
        None => out.push(0),
    }
    out
}

fn p2p_append_liquidity(out: &mut Vec<u8>, pool: &AtomicLiquidityPoolState) {
    out.extend_from_slice(&pool.pool_nonce.to_le_bytes());
    out.push(pool.curve_version);
    out.push(pool.curve_mode);
    out.extend_from_slice(&pool.individual_virtual_cpay_reserves_sompi.to_le_bytes());
    out.extend_from_slice(&pool.individual_virtual_token_multiplier_bps.to_le_bytes());
    out.extend_from_slice(&pool.real_cpay_reserves_sompi.to_le_bytes());
    out.extend_from_slice(&pool.real_token_reserves.to_le_bytes());
    out.extend_from_slice(&pool.virtual_cpay_reserves_sompi.to_le_bytes());
    out.extend_from_slice(&pool.virtual_token_reserves.to_le_bytes());
    out.extend_from_slice(&pool.unclaimed_fee_total_sompi.to_le_bytes());
    out.extend_from_slice(&pool.fee_bps.to_le_bytes());
    out.extend_from_slice(&(pool.fee_recipients.len() as u64).to_le_bytes());
    for recipient in pool.fee_recipients.iter() {
        out.extend_from_slice(&recipient.owner_id);
        out.push(recipient.address_version);
        p2p_push_bytes(out, &recipient.address_payload);
        out.extend_from_slice(&recipient.unclaimed_sompi.to_le_bytes());
    }
    out.extend_from_slice(&pool.vault_outpoint.transaction_id.as_bytes());
    out.extend_from_slice(&pool.vault_outpoint.index.to_le_bytes());
    out.extend_from_slice(&pool.vault_value_sompi.to_le_bytes());
    out.extend_from_slice(&pool.unlock_target_sompi.to_le_bytes());
    out.push(u8::from(pool.unlocked));
}

fn p2p_push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn apply_p2p_root_leaf(buckets: &mut [[u8; 32]; ATOMIC_P2P_ROOT_BUCKETS], logical_key: &[u8], value: &[u8]) {
    let leaf_hash = p2p_root_leaf_hash(logical_key, value);
    let bucket_index = p2p_root_bucket_index(logical_key);
    xor_hash_in_place(&mut buckets[bucket_index], &leaf_hash);
}

fn p2p_root_leaf_hash(logical_key: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bParams::new().hash_length(32).to_state();
    hasher.update(ATOMIC_P2P_ROOT_LEAF_DOMAIN);
    hasher.update(&(logical_key.len() as u64).to_le_bytes());
    hasher.update(logical_key);
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_bytes());
    out
}

fn p2p_root_bucket_index(logical_key: &[u8]) -> usize {
    let mut hasher = Blake2bParams::new().hash_length(32).to_state();
    hasher.update(ATOMIC_P2P_ROOT_BUCKET_INDEX_DOMAIN);
    hasher.update(logical_key);
    let digest = hasher.finalize();
    let bytes = digest.as_bytes();
    (((bytes[0] as usize) << 4) | ((bytes[1] as usize) >> 4)) & (ATOMIC_P2P_ROOT_BUCKETS - 1)
}

fn p2p_root_from_buckets(buckets: &[[u8; 32]; ATOMIC_P2P_ROOT_BUCKETS]) -> [u8; 32] {
    let mut hasher = Blake2bParams::new().hash_length(32).to_state();
    hasher.update(ATOMIC_P2P_ROOT_BUCKET_DOMAIN);
    hasher.update(&(ATOMIC_P2P_ROOT_BUCKETS as u64).to_le_bytes());
    for bucket in buckets {
        hasher.update(bucket);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_bytes());
    out
}

fn atomic_asset_class_to_u8(value: AtomicAssetClass) -> u8 {
    match value {
        AtomicAssetClass::Standard => 0,
        AtomicAssetClass::Liquidity => 1,
    }
}

fn atomic_supply_mode_to_u8(value: AtomicSupplyMode) -> u8 {
    match value {
        AtomicSupplyMode::Uncapped => 0,
        AtomicSupplyMode::Capped => 1,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AtomicConsensusStateRootRecord {
    pub state_hash: [u8; 32],
    pub nonce_changes: u32,
    pub asset_changes: u32,
    pub balance_changes: u32,
    pub anchor_count_changes: u32,
}

impl AtomicConsensusStateRootRecord {
    pub fn new(state_hash: [u8; 32], delta: &AtomicConsensusStateDelta) -> Self {
        Self {
            state_hash,
            nonce_changes: delta.nonce_changes.len() as u32,
            asset_changes: delta.asset_changes.len() as u32,
            balance_changes: delta.balance_changes.len() as u32,
            anchor_count_changes: delta.anchor_count_changes.len() as u32,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct AtomicConsensusStateRootEntry(Arc<AtomicConsensusStateRootRecord>);

#[derive(Clone, Serialize, Deserialize)]
struct AtomicConsensusStateDeltaEntry(Arc<AtomicConsensusStateDelta>);

impl MemSizeEstimator for AtomicConsensusStateRootEntry {
    fn estimate_mem_bytes(&self) -> usize {
        size_of::<Self>() + size_of::<AtomicConsensusStateRootRecord>()
    }
}

impl MemSizeEstimator for AtomicConsensusStateDeltaEntry {
    fn estimate_mem_bytes(&self) -> usize {
        let delta = self.0.as_ref();
        let asset_heap: usize = delta
            .asset_changes
            .iter()
            .map(|change| asset_delta_heap(change.old_value.as_ref()) + asset_delta_heap(change.new_value.as_ref()))
            .sum();
        size_of::<Self>()
            + delta.nonce_changes.len() * size_of::<AtomicNonceChange>()
            + delta.asset_changes.len() * size_of::<AtomicAssetChange>()
            + delta.balance_changes.len() * size_of::<AtomicBalanceChange>()
            + delta.anchor_count_changes.len() * size_of::<AtomicAnchorCountChange>()
            + asset_heap
    }
}

fn asset_delta_heap(asset: Option<&AtomicAssetState>) -> usize {
    let Some(asset) = asset else {
        return 0;
    };
    asset.name.len()
        + asset.symbol.len()
        + asset.metadata.len()
        + asset.platform_tag.len()
        + asset
            .liquidity
            .as_ref()
            .map(|pool| {
                pool.fee_recipients
                    .iter()
                    .map(|recipient| size_of::<AtomicLiquidityFeeRecipientState>() + recipient.address_payload.len())
                    .sum::<usize>()
            })
            .unwrap_or(0)
}

fn encode_nonce_key(key: &AtomicNonceKey) -> [u8; 65] {
    let mut out = [0u8; 65];
    out[..32].copy_from_slice(&key.owner_id);
    out[32] = key.scope_kind;
    out[33..].copy_from_slice(&key.scope_id);
    out
}

fn encode_balance_key(key: &AtomicBalanceKey) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&key.asset_id);
    out[32..].copy_from_slice(&key.owner_id);
    out
}

fn encode_outpoint_key(outpoint: TransactionOutpoint) -> [u8; 36] {
    let mut out = [0u8; 36];
    out[..32].copy_from_slice(&outpoint.transaction_id.as_bytes());
    out[32..].copy_from_slice(&outpoint.index.to_le_bytes());
    out
}

/// A DB + cache implementation of `DbAtomicStateStore` trait, with concurrency support.
#[derive(Clone)]
pub struct DbAtomicStateStore {
    db: Arc<DB>,
    root_access: CachedDbAccess<Hash, AtomicConsensusStateRootEntry, BlockHasher>,
    delta_access: CachedDbAccess<Hash, AtomicConsensusStateDeltaEntry, BlockHasher>,
}

impl DbAtomicStateStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self {
            db: Arc::clone(&db),
            root_access: CachedDbAccess::new(db.clone(), cache_policy, atomic_state_subprefix(ATOMIC_STATE_ROOT_SUBPREFIX)),
            delta_access: CachedDbAccess::new(db, cache_policy, atomic_state_subprefix(ATOMIC_STATE_DELTA_SUBPREFIX)),
        }
    }

    pub fn clone_with_new_cache(&self, cache_policy: CachePolicy) -> Self {
        Self::new(Arc::clone(&self.db), cache_policy)
    }

    pub fn attach_virtual_state(&self, state: &AtomicConsensusState) -> AtomicConsensusState {
        let expected = state.root_accumulator();
        match self.read_current_root() {
            Ok(Some(actual)) if actual == expected => {}
            Ok(Some(actual)) => panic!(
                "Atomic consensus current-state root mismatch: virtual={}, current={}",
                faster_hex::hex_string(&expected.hash()),
                faster_hex::hex_string(&actual.hash())
            ),
            Ok(None) if state.has_in_memory_values() => {
                let mut batch = WriteBatch::default();
                self.write_current_overlay_batch(&mut batch, state)
                    .unwrap_or_else(|err| panic!("failed migrating legacy in-memory Atomic consensus state into V2 current store: {err}"));
                self.db
                    .write(batch)
                    .unwrap_or_else(|err| panic!("failed committing migrated Atomic consensus V2 current store: {err}"));
            }
            Ok(None) if expected == AtomicConsensusRootAccumulator::default() => {}
            Ok(None) => panic!(
                "Atomic consensus current-state KV store is missing while virtual root is {}; reset the datadir or import an Atomic V2 snapshot",
                faster_hex::hex_string(&expected.hash())
            ),
            Err(err) => panic!("failed reading Atomic consensus current-state root: {err}"),
        }
        state.as_virtual_root_state().attach_current_store(Arc::new(self.clone()))
    }

    pub fn read_current_root(&self) -> Result<Option<AtomicConsensusRootAccumulator>, StoreError> {
        let key = DbKey::new(&atomic_state_subprefix(ATOMIC_STATE_CURRENT_META_SUBPREFIX), ATOMIC_STATE_CURRENT_ROOT_KEY);
        match self.db.get_pinned(&key)? {
            Some(slice) => Ok(Some(bincode::deserialize(&slice)?)),
            None => Ok(None),
        }
    }

    pub fn read_current_nonce(&self, key: &AtomicNonceKey) -> Result<Option<u64>, StoreError> {
        read_current_value(&self.db, ATOMIC_STATE_CURRENT_NONCE_SUBPREFIX, encode_nonce_key(key))
    }

    pub fn read_current_asset(&self, asset_id: &[u8; 32]) -> Result<Option<AtomicAssetState>, StoreError> {
        read_current_value(&self.db, ATOMIC_STATE_CURRENT_ASSET_SUBPREFIX, *asset_id)
    }

    pub fn read_current_balance(&self, key: &AtomicBalanceKey) -> Result<Option<u128>, StoreError> {
        read_current_value(&self.db, ATOMIC_STATE_CURRENT_BALANCE_SUBPREFIX, encode_balance_key(key))
    }

    pub fn read_current_anchor_count(&self, owner_id: &[u8; 32]) -> Result<Option<u64>, StoreError> {
        read_current_value(&self.db, ATOMIC_STATE_CURRENT_ANCHOR_SUBPREFIX, *owner_id)
    }

    pub fn read_current_vault_asset(&self, outpoint: TransactionOutpoint) -> Result<Option<[u8; 32]>, StoreError> {
        read_current_value(&self.db, ATOMIC_STATE_CURRENT_VAULT_SUBPREFIX, encode_outpoint_key(outpoint))
    }

    pub fn current_vault_index_count_limited(&self, max_exact_count: usize) -> Result<Option<usize>, StoreError> {
        let prefix = atomic_state_subprefix(ATOMIC_STATE_CURRENT_VAULT_SUBPREFIX);
        let mut count = 0usize;
        for item in self.db.prefix_iterator(&prefix) {
            let (key, _) = item?;
            if !key.starts_with(&prefix) {
                break;
            }
            count = count.saturating_add(1);
            if count > max_exact_count {
                return Ok(None);
            }
        }
        Ok(Some(count))
    }

    pub fn apply_current_chain_path_batch(
        &self,
        batch: &mut WriteBatch,
        chain_path: &ChainPath,
        new_virtual_atomic_state: &AtomicConsensusState,
    ) -> Result<(), StoreError> {
        for removed in chain_path.removed.iter().copied() {
            let delta = self.get_delta(removed)?;
            self.apply_current_delta_batch(batch, delta.as_ref(), false)?;
        }
        for added in chain_path.added.iter().copied() {
            let delta = self.get_delta(added)?;
            self.apply_current_delta_batch(batch, delta.as_ref(), true)?;
        }
        self.write_current_root_batch(batch, new_virtual_atomic_state.root_accumulator())
    }

    pub fn write_current_overlay_batch(&self, batch: &mut WriteBatch, state: &AtomicConsensusState) -> Result<(), StoreError> {
        for key in state.deleted_nonces.iter() {
            write_current_value::<u64, _>(batch, ATOMIC_STATE_CURRENT_NONCE_SUBPREFIX, encode_nonce_key(key), None)?;
        }
        for (key, value) in state.next_nonces.iter() {
            write_current_value(batch, ATOMIC_STATE_CURRENT_NONCE_SUBPREFIX, encode_nonce_key(key), Some(*value))?;
        }

        for outpoint in state.deleted_vault_outpoints.iter().copied() {
            write_current_value::<[u8; 32], _>(batch, ATOMIC_STATE_CURRENT_VAULT_SUBPREFIX, encode_outpoint_key(outpoint), None)?;
        }
        for asset_id in state.deleted_assets.iter().copied() {
            write_current_value::<AtomicAssetState, _>(batch, ATOMIC_STATE_CURRENT_ASSET_SUBPREFIX, asset_id, None)?;
        }
        for (asset_id, asset) in state.assets.iter() {
            write_current_value(batch, ATOMIC_STATE_CURRENT_ASSET_SUBPREFIX, *asset_id, Some(asset.clone()))?;
        }
        for (outpoint, asset_id) in state.liquidity_vault_outpoints.iter() {
            write_current_value(batch, ATOMIC_STATE_CURRENT_VAULT_SUBPREFIX, encode_outpoint_key(*outpoint), Some(*asset_id))?;
        }

        for key in state.deleted_balances.iter() {
            write_current_value::<u128, _>(batch, ATOMIC_STATE_CURRENT_BALANCE_SUBPREFIX, encode_balance_key(key), None)?;
        }
        for (key, value) in state.balances.iter() {
            write_current_value(batch, ATOMIC_STATE_CURRENT_BALANCE_SUBPREFIX, encode_balance_key(key), Some(*value))?;
        }

        for owner_id in state.deleted_anchor_counts.iter().copied() {
            write_current_value::<u64, _>(batch, ATOMIC_STATE_CURRENT_ANCHOR_SUBPREFIX, owner_id, None)?;
        }
        for (owner_id, value) in state.anchor_counts.iter() {
            write_current_value(batch, ATOMIC_STATE_CURRENT_ANCHOR_SUBPREFIX, *owner_id, Some(*value))?;
        }

        self.write_current_root_batch(batch, state.root_accumulator())
    }

    pub fn replace_current_overlay_batch(&self, batch: &mut WriteBatch, state: &AtomicConsensusState) -> Result<(), StoreError> {
        for tag in [
            ATOMIC_STATE_CURRENT_META_SUBPREFIX,
            ATOMIC_STATE_CURRENT_NONCE_SUBPREFIX,
            ATOMIC_STATE_CURRENT_ASSET_SUBPREFIX,
            ATOMIC_STATE_CURRENT_BALANCE_SUBPREFIX,
            ATOMIC_STATE_CURRENT_ANCHOR_SUBPREFIX,
            ATOMIC_STATE_CURRENT_VAULT_SUBPREFIX,
        ] {
            self.clear_current_subprefix_batch(batch, tag)?;
        }
        self.write_current_overlay_batch(batch, state)
    }

    fn clear_current_subprefix_batch(&self, batch: &mut WriteBatch, tag: u8) -> Result<(), StoreError> {
        let prefix = atomic_state_subprefix(tag);
        for item in self.db.prefix_iterator(&prefix) {
            let (key, _) = item?;
            if !key.starts_with(&prefix) {
                break;
            }
            batch.delete(key);
        }
        Ok(())
    }

    pub fn materialize_current_state(&self, root_state: &AtomicConsensusState) -> Result<AtomicConsensusState, StoreError> {
        let mut state = AtomicConsensusState::default();
        state.root_accumulator = root_state.root_accumulator();

        for (raw_key, value) in self.current_iterator::<u64>(ATOMIC_STATE_CURRENT_NONCE_SUBPREFIX)? {
            if raw_key.len() != 65 {
                return Err(StoreError::DataInconsistency(format!("invalid current Atomic nonce key length {}", raw_key.len())));
            }
            let mut owner_id = [0u8; 32];
            owner_id.copy_from_slice(&raw_key[..32]);
            let scope_kind = raw_key[32];
            let mut scope_id = [0u8; 32];
            scope_id.copy_from_slice(&raw_key[33..65]);
            state.next_nonces.insert(AtomicNonceKey { owner_id, scope_kind, scope_id }, value);
        }
        for (raw_key, value) in self.current_iterator::<AtomicAssetState>(ATOMIC_STATE_CURRENT_ASSET_SUBPREFIX)? {
            if raw_key.len() != 32 {
                return Err(StoreError::DataInconsistency(format!("invalid current Atomic asset key length {}", raw_key.len())));
            }
            let mut asset_id = [0u8; 32];
            asset_id.copy_from_slice(&raw_key);
            state.assets.insert(asset_id, value);
        }
        for (raw_key, value) in self.current_iterator::<u128>(ATOMIC_STATE_CURRENT_BALANCE_SUBPREFIX)? {
            if raw_key.len() != 64 {
                return Err(StoreError::DataInconsistency(format!("invalid current Atomic balance key length {}", raw_key.len())));
            }
            let mut asset_id = [0u8; 32];
            asset_id.copy_from_slice(&raw_key[..32]);
            let mut owner_id = [0u8; 32];
            owner_id.copy_from_slice(&raw_key[32..64]);
            state.balances.insert(AtomicBalanceKey { asset_id, owner_id }, value);
        }
        for (raw_key, value) in self.current_iterator::<u64>(ATOMIC_STATE_CURRENT_ANCHOR_SUBPREFIX)? {
            if raw_key.len() != 32 {
                return Err(StoreError::DataInconsistency(format!(
                    "invalid current Atomic anchor-count key length {}",
                    raw_key.len()
                )));
            }
            let mut owner_id = [0u8; 32];
            owner_id.copy_from_slice(&raw_key);
            state.anchor_counts.insert(owner_id, value);
        }
        state.rebuild_liquidity_vault_outpoint_index();
        if state.canonical_hash() != root_state.canonical_hash() {
            return Err(StoreError::DataInconsistency(format!(
                "materialized current Atomic state root mismatch: expected {}, got {}",
                faster_hex::hex_string(&root_state.canonical_hash()),
                faster_hex::hex_string(&state.canonical_hash())
            )));
        }
        Ok(state)
    }

    #[cfg(test)]
    pub fn materialize_current_state_for_tests(&self, root_state: &AtomicConsensusState) -> AtomicConsensusState {
        self.materialize_current_state(root_state).expect("materialize current Atomic test state")
    }

    #[cfg(test)]
    pub fn clear_current_store_for_tests(&self) {
        let mut batch = WriteBatch::default();
        for tag in [
            ATOMIC_STATE_CURRENT_META_SUBPREFIX,
            ATOMIC_STATE_CURRENT_NONCE_SUBPREFIX,
            ATOMIC_STATE_CURRENT_ASSET_SUBPREFIX,
            ATOMIC_STATE_CURRENT_BALANCE_SUBPREFIX,
            ATOMIC_STATE_CURRENT_ANCHOR_SUBPREFIX,
            ATOMIC_STATE_CURRENT_VAULT_SUBPREFIX,
        ] {
            self.clear_current_subprefix_batch(&mut batch, tag).expect("clear current Atomic subprefix");
        }
        self.db.write(batch).expect("clear current Atomic store");
    }

    fn current_iterator<T>(&self, tag: u8) -> Result<Vec<(Vec<u8>, T)>, StoreError>
    where
        T: DeserializeOwned,
    {
        let prefix = atomic_state_subprefix(tag);
        let mut out = Vec::new();
        for item in self.db.prefix_iterator(&prefix) {
            let (key, value) = item?;
            if !key.starts_with(&prefix) {
                break;
            }
            out.push((key[prefix.len()..].to_vec(), bincode::deserialize(value.as_ref())?));
        }
        Ok(out)
    }

    fn apply_current_delta_batch(
        &self,
        batch: &mut WriteBatch,
        delta: &AtomicConsensusStateDelta,
        forward: bool,
    ) -> Result<(), StoreError> {
        for change in &delta.nonce_changes {
            let value = if forward { change.new_value } else { change.old_value };
            write_current_value(batch, ATOMIC_STATE_CURRENT_NONCE_SUBPREFIX, encode_nonce_key(&change.key), value)?;
        }
        for change in &delta.asset_changes {
            let old_value = if forward { change.old_value.as_ref() } else { change.new_value.as_ref() };
            let new_value = if forward { change.new_value.as_ref() } else { change.old_value.as_ref() };
            write_current_asset_change(batch, change.asset_id, old_value, new_value)?;
        }
        for change in &delta.balance_changes {
            let value = if forward { change.new_value } else { change.old_value };
            write_current_value(batch, ATOMIC_STATE_CURRENT_BALANCE_SUBPREFIX, encode_balance_key(&change.key), value)?;
        }
        for change in &delta.anchor_count_changes {
            let value = if forward { change.new_value } else { change.old_value };
            write_current_value(batch, ATOMIC_STATE_CURRENT_ANCHOR_SUBPREFIX, change.owner_id, value)?;
        }
        Ok(())
    }

    fn write_current_root_batch(
        &self,
        batch: &mut WriteBatch,
        root_accumulator: AtomicConsensusRootAccumulator,
    ) -> Result<(), StoreError> {
        let key = DbKey::new(&atomic_state_subprefix(ATOMIC_STATE_CURRENT_META_SUBPREFIX), ATOMIC_STATE_CURRENT_ROOT_KEY);
        batch.put(key, bincode::serialize(&root_accumulator)?);
        Ok(())
    }

    pub fn insert_batch_with_delta(
        &self,
        batch: &mut WriteBatch,
        hash: Hash,
        state_hash: [u8; 32],
        delta: Arc<AtomicConsensusStateDelta>,
    ) -> Result<(), StoreError> {
        if self.root_access.has(hash)? {
            return Err(StoreError::HashAlreadyExists(hash));
        }
        let root_record = Arc::new(AtomicConsensusStateRootRecord::new(state_hash, delta.as_ref()));
        self.root_access.write(BatchDbWriter::new(batch), hash, AtomicConsensusStateRootEntry(root_record))?;
        self.delta_access.write(BatchDbWriter::new(batch), hash, AtomicConsensusStateDeltaEntry(delta))?;
        Ok(())
    }

    pub fn repair_batch_with_delta(
        &self,
        batch: &mut WriteBatch,
        hash: Hash,
        state_hash: [u8; 32],
        delta: Arc<AtomicConsensusStateDelta>,
    ) -> Result<(), StoreError> {
        let root_record = Arc::new(AtomicConsensusStateRootRecord::new(state_hash, delta.as_ref()));
        self.root_access.write(BatchDbWriter::new(batch), hash, AtomicConsensusStateRootEntry(root_record))?;
        self.delta_access.write(BatchDbWriter::new(batch), hash, AtomicConsensusStateDeltaEntry(delta))?;
        Ok(())
    }

    pub fn insert_root_batch(&self, batch: &mut WriteBatch, hash: Hash, state_hash: [u8; 32]) -> Result<(), StoreError> {
        self.insert_batch_with_delta(batch, hash, state_hash, Arc::new(AtomicConsensusStateDelta::default()))
    }

    pub fn delete_batch(&self, batch: &mut WriteBatch, hash: Hash) -> Result<(), StoreError> {
        self.root_access.delete(BatchDbWriter::new(batch), hash)?;
        self.delta_access.delete(BatchDbWriter::new(batch), hash)
    }

    pub fn delete_records_above_daa_batch<F>(
        &self,
        batch: &mut WriteBatch,
        mut daa_for_hash: F,
        target_daa: u64,
    ) -> Result<(usize, usize), StoreError>
    where
        F: FnMut(Hash) -> Result<Option<u64>, StoreError>,
    {
        let mut to_delete = Vec::new();
        let mut deleted_above_target = 0usize;
        let mut deleted_orphans = 0usize;

        for item in self.root_access.iterator() {
            let (raw_key, _) =
                item.map_err(|err| StoreError::DataInconsistency(format!("failed iterating Atomic state roots: {err}")))?;
            if raw_key.len() != cryptix_hashes::HASH_SIZE {
                return Err(StoreError::DataInconsistency(format!(
                    "invalid Atomic state root key length {}; expected {}",
                    raw_key.len(),
                    cryptix_hashes::HASH_SIZE
                )));
            }
            let hash = Hash::from_slice(&raw_key);
            match daa_for_hash(hash)? {
                Some(daa) if daa > target_daa => {
                    deleted_above_target += 1;
                    to_delete.push(hash);
                }
                None => {
                    deleted_orphans += 1;
                    to_delete.push(hash);
                }
                _ => {}
            }
        }

        for hash in to_delete {
            match self.root_access.delete(BatchDbWriter::new(batch), hash) {
                Ok(()) | Err(StoreError::KeyNotFound(_)) => {}
                Err(err) => return Err(err),
            }
            match self.delta_access.delete(BatchDbWriter::new(batch), hash) {
                Ok(()) | Err(StoreError::KeyNotFound(_)) => {}
                Err(err) => return Err(err),
            }
        }

        Ok((deleted_above_target, deleted_orphans))
    }

    pub fn get_root_record(&self, hash: Hash) -> Result<Arc<AtomicConsensusStateRootRecord>, StoreError> {
        Ok(self.root_access.read(hash)?.0)
    }

    pub fn get_delta(&self, hash: Hash) -> Result<Arc<AtomicConsensusStateDelta>, StoreError> {
        Ok(self.delta_access.read(hash)?.0)
    }

    pub fn delete(&self, hash: Hash) -> Result<(), StoreError> {
        let mut batch = WriteBatch::default();
        self.delete_batch(&mut batch, hash)?;
        self.db.write(batch)?;
        Ok(())
    }
}

fn read_current_value<T, K>(db: &DB, tag: u8, key: K) -> Result<Option<T>, StoreError>
where
    T: DeserializeOwned,
    K: Clone + AsRef<[u8]>,
{
    let db_key = DbKey::new(&atomic_state_subprefix(tag), key);
    match db.get_pinned(&db_key)? {
        Some(slice) => Ok(Some(bincode::deserialize(&slice)?)),
        None => Ok(None),
    }
}

fn write_current_value<T, K>(batch: &mut WriteBatch, tag: u8, key: K, value: Option<T>) -> Result<(), StoreError>
where
    T: Serialize,
    K: Clone + AsRef<[u8]>,
{
    let db_key = DbKey::new(&atomic_state_subprefix(tag), key);
    match value {
        Some(value) => {
            batch.put(db_key, bincode::serialize(&value)?);
        }
        None => {
            batch.delete(db_key);
        }
    }
    Ok(())
}

fn write_current_asset_change(
    batch: &mut WriteBatch,
    asset_id: [u8; 32],
    old_value: Option<&AtomicAssetState>,
    new_value: Option<&AtomicAssetState>,
) -> Result<(), StoreError> {
    if let Some(old_asset) = old_value {
        if let Some(pool) = old_asset.liquidity.as_ref() {
            write_current_value::<[u8; 32], _>(
                batch,
                ATOMIC_STATE_CURRENT_VAULT_SUBPREFIX,
                encode_outpoint_key(pool.vault_outpoint),
                None,
            )?;
        }
    }
    write_current_value(batch, ATOMIC_STATE_CURRENT_ASSET_SUBPREFIX, asset_id, new_value.cloned())?;
    if let Some(new_asset) = new_value {
        if matches!(new_asset.asset_class, AtomicAssetClass::Liquidity) {
            if let Some(pool) = new_asset.liquidity.as_ref() {
                write_current_value(
                    batch,
                    ATOMIC_STATE_CURRENT_VAULT_SUBPREFIX,
                    encode_outpoint_key(pool.vault_outpoint),
                    Some(asset_id),
                )?;
            }
        }
    }
    Ok(())
}

fn decode_root_only_canonical_bytes(bytes: &[u8]) -> Result<Option<[u8; 32]>, String> {
    if bytes.len() != ATOMIC_CONSENSUS_STATE_MAGIC.len() + ATOMIC_CONSENSUS_STATE_ROOT_ONLY_TAG.len() + 32 {
        return Ok(None);
    }
    if !bytes.starts_with(ATOMIC_CONSENSUS_STATE_MAGIC) {
        return Err("invalid atomic consensus state magic".to_string());
    }
    let tag_start = ATOMIC_CONSENSUS_STATE_MAGIC.len();
    let tag_end = tag_start + ATOMIC_CONSENSUS_STATE_ROOT_ONLY_TAG.len();
    if &bytes[tag_start..tag_end] != ATOMIC_CONSENSUS_STATE_ROOT_ONLY_TAG {
        return Ok(None);
    }
    let mut state_hash = [0u8; 32];
    state_hash.copy_from_slice(&bytes[tag_end..]);
    Ok(Some(state_hash))
}

fn write_len(out: &mut Vec<u8>, len: usize) {
    write_u64(out, len as u64);
}

fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u128(out: &mut Vec<u8>, value: u128) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_optional_hash(out: &mut Vec<u8>, value: &Option<[u8; 32]>) {
    match value {
        Some(hash) => {
            out.push(1);
            out.extend_from_slice(hash);
        }
        None => out.push(0),
    }
}

fn write_optional_u64(out: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            out.push(1);
            write_u64(out, value);
        }
        None => out.push(0),
    }
}

fn write_atomic_asset(out: &mut Vec<u8>, asset: &AtomicAssetState) {
    out.extend_from_slice(&asset.creator_owner_id);
    out.push(match asset.asset_class {
        AtomicAssetClass::Standard => 0,
        AtomicAssetClass::Liquidity => 1,
    });
    out.push(asset.token_version);
    out.extend_from_slice(&asset.mint_authority_owner_id);
    out.push(asset.decimals);
    out.push(match asset.supply_mode {
        AtomicSupplyMode::Uncapped => 0,
        AtomicSupplyMode::Capped => 1,
    });
    write_u128(out, asset.max_supply);
    write_u128(out, asset.total_supply);
    write_len(out, asset.name.len());
    out.extend_from_slice(&asset.name);
    write_len(out, asset.symbol.len());
    out.extend_from_slice(&asset.symbol);
    write_len(out, asset.metadata.len());
    out.extend_from_slice(&asset.metadata);
    write_len(out, asset.platform_tag.len());
    out.extend_from_slice(&asset.platform_tag);
    write_optional_hash(out, &asset.created_block_hash);
    write_optional_u64(out, asset.created_daa_score);
    write_optional_u64(out, asset.created_at);
    match asset.liquidity.as_ref() {
        Some(pool) => {
            out.push(1);
            write_liquidity_pool(out, pool);
        }
        None => out.push(0),
    }
}

fn write_liquidity_pool(out: &mut Vec<u8>, pool: &AtomicLiquidityPoolState) {
    write_u64(out, pool.pool_nonce);
    out.push(pool.curve_version);
    out.push(pool.curve_mode);
    write_u64(out, pool.individual_virtual_cpay_reserves_sompi);
    write_u16(out, pool.individual_virtual_token_multiplier_bps);
    write_u64(out, pool.real_cpay_reserves_sompi);
    write_u128(out, pool.real_token_reserves);
    write_u64(out, pool.virtual_cpay_reserves_sompi);
    write_u128(out, pool.virtual_token_reserves);
    write_u64(out, pool.unclaimed_fee_total_sompi);
    write_u16(out, pool.fee_bps);
    write_len(out, pool.fee_recipients.len());
    for recipient in &pool.fee_recipients {
        out.extend_from_slice(&recipient.owner_id);
        out.push(recipient.address_version);
        write_len(out, recipient.address_payload.len());
        out.extend_from_slice(&recipient.address_payload);
        write_u64(out, recipient.unclaimed_sompi);
    }
    out.extend_from_slice(&pool.vault_outpoint.transaction_id.as_bytes());
    write_u32(out, pool.vault_outpoint.index);
    write_u64(out, pool.vault_value_sompi);
    write_u64(out, pool.unlock_target_sompi);
    out.push(u8::from(pool.unlocked));
}

struct AtomicStateReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> AtomicStateReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self.cursor.checked_add(len).ok_or_else(|| "truncated atomic consensus state".to_string())?;
        if end > self.bytes.len() {
            return Err("truncated atomic consensus state".to_string());
        }
        let out = &self.bytes[self.cursor..end];
        self.cursor = end;
        Ok(out)
    }

    fn read_exact_magic(&mut self, magic: &[u8]) -> Result<(), String> {
        let actual = self.read_bytes(magic.len())?;
        if actual == magic {
            Ok(())
        } else {
            Err("invalid atomic consensus state magic".to_string())
        }
    }

    fn read_hash32(&mut self) -> Result<[u8; 32], String> {
        let bytes = self.read_bytes(32)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    fn read_u8(&mut self) -> Result<u8, String> {
        Ok(self.read_bytes(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, String> {
        let mut bytes = [0u8; 2];
        bytes.copy_from_slice(self.read_bytes(2)?);
        Ok(u16::from_le_bytes(bytes))
    }

    fn read_u32(&mut self) -> Result<u32, String> {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(self.read_bytes(4)?);
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_u64(&mut self) -> Result<u64, String> {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(self.read_bytes(8)?);
        Ok(u64::from_le_bytes(bytes))
    }

    fn read_u128(&mut self) -> Result<u128, String> {
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(self.read_bytes(16)?);
        Ok(u128::from_le_bytes(bytes))
    }

    fn read_optional_hash32(&mut self) -> Result<Option<[u8; 32]>, String> {
        match self.read_u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.read_hash32()?)),
            raw => Err(format!("invalid optional hash presence flag `{raw}`")),
        }
    }

    fn read_optional_u64(&mut self) -> Result<Option<u64>, String> {
        match self.read_u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.read_u64()?)),
            raw => Err(format!("invalid optional u64 presence flag `{raw}`")),
        }
    }

    fn read_len(&mut self) -> Result<u64, String> {
        self.read_u64()
    }

    fn read_len_usize(&mut self, context: &str) -> Result<usize, String> {
        let len = self.read_len()?;
        usize::try_from(len).map_err(|_| format!("{context} length `{len}` exceeds platform limit"))
    }

    fn read_atomic_asset(&mut self) -> Result<AtomicAssetState, String> {
        let cursor = self.cursor;
        match self.read_current_atomic_asset() {
            Ok(asset) => Ok(asset),
            Err(err) => {
                self.cursor = cursor;
                self.read_legacy_atomic_asset().map_err(|_| err)
            }
        }
    }

    fn read_current_atomic_asset(&mut self) -> Result<AtomicAssetState, String> {
        let creator_owner_id = self.read_hash32()?;
        let asset_class = match self.read_u8()? {
            0 => AtomicAssetClass::Standard,
            1 => AtomicAssetClass::Liquidity,
            raw => return Err(format!("invalid atomic asset class `{raw}`")),
        };
        let token_version = self.read_u8()?;
        validate_token_version(token_version)?;
        let mint_authority_owner_id = self.read_hash32()?;
        let decimals = self.read_u8()?;
        if decimals > MAX_ATOMIC_DECIMALS {
            return Err(format!("atomic decimals `{decimals}` above max `{MAX_ATOMIC_DECIMALS}`"));
        }
        let supply_mode = match self.read_u8()? {
            0 => AtomicSupplyMode::Uncapped,
            1 => AtomicSupplyMode::Capped,
            raw => return Err(format!("invalid atomic supply mode `{raw}`")),
        };
        let max_supply = self.read_u128()?;
        let total_supply = self.read_u128()?;
        let name_len = self.read_len_usize("atomic name")?;
        if name_len > MAX_ATOMIC_NAME_LEN {
            return Err(format!("atomic name length `{name_len}` exceeds max"));
        }
        let name = self.read_bytes(name_len)?.to_vec();
        let symbol_len = self.read_len_usize("atomic symbol")?;
        if symbol_len > MAX_ATOMIC_SYMBOL_LEN {
            return Err(format!("atomic symbol length `{symbol_len}` exceeds max"));
        }
        let symbol = self.read_bytes(symbol_len)?.to_vec();
        let metadata_len = self.read_len_usize("atomic metadata")?;
        if metadata_len > MAX_ATOMIC_METADATA_LEN {
            return Err(format!("atomic metadata length `{metadata_len}` exceeds max"));
        }
        let metadata = self.read_bytes(metadata_len)?.to_vec();
        if std::str::from_utf8(&name).is_err() || std::str::from_utf8(&symbol).is_err() {
            return Err("atomic name/symbol must be valid utf-8".to_string());
        }
        let platform_tag_len = self.read_len_usize("atomic platform tag")?;
        if platform_tag_len > MAX_ATOMIC_PLATFORM_TAG_LEN {
            return Err(format!("atomic platform tag length `{platform_tag_len}` exceeds max"));
        }
        let platform_tag = self.read_bytes(platform_tag_len)?.to_vec();
        std::str::from_utf8(&platform_tag).map_err(|_| "atomic platform tag must be valid utf-8".to_string())?;
        let created_block_hash = self.read_optional_hash32()?;
        let created_daa_score = self.read_optional_u64()?;
        let created_at = self.read_optional_u64()?;
        let liquidity = match self.read_u8()? {
            0 => None,
            1 => Some(self.read_liquidity_pool()?),
            raw => return Err(format!("invalid atomic liquidity presence flag `{raw}`")),
        };
        Ok(AtomicAssetState {
            creator_owner_id,
            asset_class,
            token_version,
            mint_authority_owner_id,
            decimals,
            supply_mode,
            max_supply,
            total_supply,
            name,
            symbol,
            metadata,
            platform_tag,
            created_block_hash,
            created_daa_score,
            created_at,
            liquidity,
        })
    }

    fn read_legacy_atomic_asset(&mut self) -> Result<AtomicAssetState, String> {
        let asset_class = match self.read_u8()? {
            0 => AtomicAssetClass::Standard,
            1 => AtomicAssetClass::Liquidity,
            raw => return Err(format!("invalid atomic asset class `{raw}`")),
        };
        let token_version = self.read_u8()?;
        validate_token_version(token_version)?;
        let mint_authority_owner_id = self.read_hash32()?;
        let supply_mode = match self.read_u8()? {
            0 => AtomicSupplyMode::Uncapped,
            1 => AtomicSupplyMode::Capped,
            raw => return Err(format!("invalid atomic supply mode `{raw}`")),
        };
        let max_supply = self.read_u128()?;
        let total_supply = self.read_u128()?;
        let platform_tag_len = self.read_len_usize("atomic platform tag")?;
        if platform_tag_len > MAX_ATOMIC_PLATFORM_TAG_LEN {
            return Err(format!("atomic platform tag length `{platform_tag_len}` exceeds max"));
        }
        let platform_tag = self.read_bytes(platform_tag_len)?.to_vec();
        std::str::from_utf8(&platform_tag).map_err(|_| "atomic platform tag must be valid utf-8".to_string())?;
        let liquidity = match self.read_u8()? {
            0 => None,
            1 => Some(self.read_liquidity_pool()?),
            raw => return Err(format!("invalid atomic liquidity presence flag `{raw}`")),
        };
        Ok(AtomicAssetState {
            creator_owner_id: [0u8; 32],
            asset_class,
            token_version,
            mint_authority_owner_id,
            decimals: 0,
            supply_mode,
            max_supply,
            total_supply,
            name: Vec::new(),
            symbol: Vec::new(),
            metadata: Vec::new(),
            platform_tag,
            created_block_hash: None,
            created_daa_score: None,
            created_at: None,
            liquidity,
        })
    }

    fn read_liquidity_pool(&mut self) -> Result<AtomicLiquidityPoolState, String> {
        let pool_nonce = self.read_u64()?;
        let curve_version = self.read_u8()?;
        validate_liquidity_curve_version(curve_version)?;
        let curve_mode = self.read_u8()?;
        validate_liquidity_curve_mode(curve_mode)?;
        let individual_virtual_cpay_reserves_sompi = self.read_u64()?;
        let individual_virtual_token_multiplier_bps = self.read_u16()?;
        validate_liquidity_curve_parameters(
            curve_mode,
            individual_virtual_cpay_reserves_sompi,
            individual_virtual_token_multiplier_bps,
        )?;
        let real_cpay_reserves_sompi = self.read_u64()?;
        let real_token_reserves = self.read_u128()?;
        let virtual_cpay_reserves_sompi = self.read_u64()?;
        let virtual_token_reserves = self.read_u128()?;
        let unclaimed_fee_total_sompi = self.read_u64()?;
        let fee_bps = self.read_u16()?;
        let recipient_count = self.read_len_usize("atomic liquidity recipient")?;
        if recipient_count > MAX_ATOMIC_LIQUIDITY_FEE_RECIPIENTS {
            return Err(format!("atomic liquidity recipient count `{recipient_count}` exceeds max"));
        }
        let mut fee_recipients = Vec::with_capacity(recipient_count);
        for _ in 0..recipient_count {
            let owner_id = self.read_hash32()?;
            let address_version = self.read_u8()?;
            let address_payload_len = self.read_len_usize("atomic liquidity recipient address payload")?;
            let address_payload = self.read_bytes(address_payload_len)?.to_vec();
            let unclaimed_sompi = self.read_u64()?;
            fee_recipients.push(AtomicLiquidityFeeRecipientState { owner_id, address_version, address_payload, unclaimed_sompi });
        }
        let transaction_id = Hash::from_bytes(self.read_hash32()?);
        let index = self.read_u32()?;
        let vault_value_sompi = self.read_u64()?;
        let unlock_target_sompi = self.read_u64()?;
        let unlocked = match self.read_u8()? {
            0 => false,
            1 => true,
            raw => return Err(format!("invalid atomic liquidity unlocked flag `{raw}`")),
        };
        Ok(AtomicLiquidityPoolState {
            pool_nonce,
            curve_version,
            curve_mode,
            individual_virtual_cpay_reserves_sompi,
            individual_virtual_token_multiplier_bps,
            real_cpay_reserves_sompi,
            real_token_reserves,
            virtual_cpay_reserves_sompi,
            virtual_token_reserves,
            unclaimed_fee_total_sompi,
            fee_bps,
            fee_recipients,
            vault_outpoint: TransactionOutpoint::new(transaction_id, index),
            vault_value_sompi,
            unlock_target_sompi,
            unlocked,
        })
    }

    fn finish(&self) -> Result<(), String> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err("unexpected trailing bytes in atomic consensus state".to_string())
        }
    }
}

fn atomic_state_subprefix(tag: u8) -> Vec<u8> {
    let mut prefix: Vec<u8> = DatabaseStorePrefixes::AtomicStateV2.into();
    prefix.push(tag);
    prefix
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptix_database::{create_temp_db, prelude::ConnBuilder};

    fn owner(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn hash(byte: u8) -> Hash {
        Hash::from_bytes([byte; 32])
    }

    fn seq_bytes32(start: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = start.wrapping_add(index as u8);
        }
        out
    }

    fn u128_from_words(hi: u64, lo: u64) -> u128 {
        ((hi as u128) << 64) | lo as u128
    }

    fn atomic_interop_vector_state() -> AtomicConsensusState {
        let standard_asset_id = [0x10; 32];
        let liquidity_asset_id = [0x20; 32];

        let standard_total = u128_from_words(0x0100, 12_345);
        let standard_balance_a = u128_from_words(0x0080, 1_000);
        let standard_balance_b = standard_total - standard_balance_a;

        let liquidity_total = u128_from_words(0x8000, 333);
        let liquidity_remaining = u128_from_words(0x8000, 999_667);
        let liquidity_max_supply = liquidity_total + liquidity_remaining;

        let fee_recipient_payload_a = vec![0x01; 32];
        let fee_recipient_payload_b = vec![0x02; 32];
        let fee_recipient_owner_a =
            atomic_owner_id_from_address_components(0, &fee_recipient_payload_a).expect("valid recipient owner A");
        let fee_recipient_owner_b =
            atomic_owner_id_from_address_components(0, &fee_recipient_payload_b).expect("valid recipient owner B");

        let standard_asset = AtomicAssetState {
            creator_owner_id: owner(0xA0),
            asset_class: AtomicAssetClass::Standard,
            token_version: ATOMIC_CURRENT_TOKEN_VERSION,
            mint_authority_owner_id: owner(0xA1),
            decimals: 8,
            supply_mode: AtomicSupplyMode::Capped,
            max_supply: u128_from_words(0x0200, 9_999),
            total_supply: standard_total,
            name: b"Interop Standard Token".to_vec(),
            symbol: b"IST".to_vec(),
            metadata: b"{\"interop\":true}".to_vec(),
            platform_tag: Vec::new(),
            created_block_hash: Some(owner(0xC0)),
            created_daa_score: Some(12_345),
            created_at: Some(1_715_000_000_000),
            liquidity: None,
        };
        let liquidity_asset = AtomicAssetState {
            creator_owner_id: owner(0xA2),
            asset_class: AtomicAssetClass::Liquidity,
            token_version: ATOMIC_CURRENT_TOKEN_VERSION,
            mint_authority_owner_id: [0; 32],
            decimals: 0,
            supply_mode: AtomicSupplyMode::Capped,
            max_supply: liquidity_max_supply,
            total_supply: liquidity_total,
            name: b"Interop Liquidity Token".to_vec(),
            symbol: b"ILT".to_vec(),
            metadata: b"{\"pool\":17}".to_vec(),
            platform_tag: Vec::new(),
            created_block_hash: Some(owner(0xC1)),
            created_daa_score: Some(12_346),
            created_at: Some(1_715_000_000_001),
            liquidity: Some(AtomicLiquidityPoolState {
                pool_nonce: 17,
                curve_version: ATOMIC_CURRENT_LIQUIDITY_CURVE_VERSION,
                curve_mode: ATOMIC_DEFAULT_LIQUIDITY_CURVE_MODE,
                individual_virtual_cpay_reserves_sompi: 0,
                individual_virtual_token_multiplier_bps: 0,
                real_cpay_reserves_sompi: 123_456_789,
                real_token_reserves: liquidity_remaining,
                virtual_cpay_reserves_sompi: 1_000_000_000_000,
                virtual_token_reserves: 1_300_000,
                unclaimed_fee_total_sompi: 30,
                fee_bps: 250,
                fee_recipients: vec![
                    AtomicLiquidityFeeRecipientState {
                        owner_id: fee_recipient_owner_a,
                        address_version: 0,
                        address_payload: fee_recipient_payload_a,
                        unclaimed_sompi: 10,
                    },
                    AtomicLiquidityFeeRecipientState {
                        owner_id: fee_recipient_owner_b,
                        address_version: 0,
                        address_payload: fee_recipient_payload_b,
                        unclaimed_sompi: 20,
                    },
                ],
                vault_outpoint: TransactionOutpoint::new(hash(0x77), 3),
                vault_value_sompi: 123_456_819,
                unlock_target_sompi: 0,
                unlocked: true,
            }),
        };

        let mut state = AtomicConsensusState::default();
        state.next_nonces.insert(AtomicNonceKey::owner(owner(0x61)), 3);
        state.next_nonces.insert(AtomicNonceKey::asset(owner(0x60), standard_asset_id), 99);
        state.assets.insert(liquidity_asset_id, liquidity_asset);
        state.assets.insert(standard_asset_id, standard_asset);
        state.balances.insert(AtomicBalanceKey { asset_id: standard_asset_id, owner_id: owner(0xB1) }, standard_balance_b);
        state.balances.insert(AtomicBalanceKey { asset_id: liquidity_asset_id, owner_id: owner(0xC0) }, liquidity_total);
        state.balances.insert(AtomicBalanceKey { asset_id: standard_asset_id, owner_id: owner(0xB0) }, standard_balance_a);
        state.anchor_counts.insert(owner(0x51), 2);
        state.anchor_counts.insert(owner(0x50), 9);
        state.rebuild_liquidity_vault_outpoint_index();
        state
    }

    fn atomic_interop_vector_json() -> serde_json::Value {
        let state = atomic_interop_vector_state();
        state.validate_normalized().expect("interop vector state must be normalized");
        let state_hash = state.canonical_hash();
        let raw_utxo_commitment = hash(0x31);
        let pre_hf_commitment = AtomicConsensusState::header_commitment(raw_utxo_commitment, state_hash, false);
        let post_hf_commitment = AtomicConsensusState::header_commitment(raw_utxo_commitment, state_hash, true);

        serde_json::json!({
            "name": "cryptix-atomic-consensus-state-root-v2",
            "state_hash_hex": faster_hex::hex_string(&state_hash),
            "raw_utxo_commitment_hex": raw_utxo_commitment.to_string(),
            "header_commitment_pre_hf_hex": pre_hf_commitment.to_string(),
            "header_commitment_post_hf_hex": post_hf_commitment.to_string()
        })
    }

    #[test]
    fn header_commitment_is_legacy_before_hf_and_binds_atomic_state_after_hf() {
        let utxo_commitment = hash(1);
        let atomic_hash_a = [2u8; 32];
        let atomic_hash_b = [3u8; 32];

        assert_eq!(AtomicConsensusState::header_commitment(utxo_commitment, atomic_hash_a, false), utxo_commitment);

        let commitment_a = AtomicConsensusState::header_commitment(utxo_commitment, atomic_hash_a, true);
        let commitment_b = AtomicConsensusState::header_commitment(utxo_commitment, atomic_hash_b, true);
        assert_ne!(commitment_a, utxo_commitment);
        assert_ne!(commitment_a, commitment_b);
    }

    #[test]
    fn p2p_token_audit_hash_matches_go_complex_vector() {
        let asset_a = seq_bytes32(0x10);
        let asset_b = seq_bytes32(0x40);
        let owner_a = seq_bytes32(0x70);
        let owner_b = seq_bytes32(0x90);
        let creator_a = seq_bytes32(0xB0);
        let creator_b = seq_bytes32(0xC0);
        let authority_a = seq_bytes32(0xD0);
        let recipient_a = seq_bytes32(0xE0);
        let recipient_b = seq_bytes32(0xF0);
        let created_a = seq_bytes32(0x21);
        let created_b = seq_bytes32(0x31);
        let vault_txid = Hash::from_bytes(seq_bytes32(0x55));

        let mut state = AtomicConsensusState::default();
        state.assets.insert(
            asset_a,
            AtomicAssetState {
                creator_owner_id: creator_a,
                asset_class: AtomicAssetClass::Standard,
                token_version: ATOMIC_CURRENT_TOKEN_VERSION,
                mint_authority_owner_id: authority_a,
                decimals: 8,
                supply_mode: AtomicSupplyMode::Capped,
                max_supply: 9_000_000,
                total_supply: 1_234_567,
                name: b"VectorToken".to_vec(),
                symbol: b"VEC".to_vec(),
                metadata: vec![0x01, 0x02, 0x03, 0x04],
                platform_tag: b"audit-v1".to_vec(),
                created_block_hash: Some(created_a),
                created_daa_score: Some(12_345),
                created_at: Some(1_779_700_001),
                liquidity: None,
            },
        );
        state.assets.insert(
            asset_b,
            AtomicAssetState {
                creator_owner_id: creator_b,
                asset_class: AtomicAssetClass::Liquidity,
                token_version: ATOMIC_CURRENT_TOKEN_VERSION,
                mint_authority_owner_id: [0u8; 32],
                decimals: 6,
                supply_mode: AtomicSupplyMode::Capped,
                max_supply: 2_000_000,
                total_supply: 777_000,
                name: b"LiquidityVector".to_vec(),
                symbol: b"LVEC".to_vec(),
                metadata: vec![0xAA, 0xBB, 0xCC],
                platform_tag: b"pool-v2".to_vec(),
                created_block_hash: Some(created_b),
                created_daa_score: Some(12_678),
                created_at: Some(1_779_700_999),
                liquidity: Some(AtomicLiquidityPoolState {
                    pool_nonce: 44,
                    curve_version: ATOMIC_CURRENT_LIQUIDITY_CURVE_VERSION,
                    curve_mode: ATOMIC_LIQUIDITY_CURVE_MODE_INDIVIDUAL,
                    individual_virtual_cpay_reserves_sompi: 12_000,
                    individual_virtual_token_multiplier_bps: 150,
                    real_cpay_reserves_sompi: 9_876_543,
                    real_token_reserves: 123_456,
                    virtual_cpay_reserves_sompi: 10_000_000,
                    virtual_token_reserves: 654_321,
                    unclaimed_fee_total_sompi: 333,
                    fee_bps: 25,
                    fee_recipients: vec![
                        AtomicLiquidityFeeRecipientState {
                            owner_id: recipient_a,
                            address_version: 0,
                            address_payload: vec![0x10, 0x11],
                            unclaimed_sompi: 7,
                        },
                        AtomicLiquidityFeeRecipientState {
                            owner_id: recipient_b,
                            address_version: 1,
                            address_payload: vec![0x20, 0x21, 0x22],
                            unclaimed_sompi: 11,
                        },
                    ],
                    vault_outpoint: TransactionOutpoint::new(vault_txid, 3),
                    vault_value_sompi: 8_888,
                    unlock_target_sompi: 99_999,
                    unlocked: false,
                }),
            },
        );
        state.balances.insert(AtomicBalanceKey { asset_id: asset_a, owner_id: owner_a }, 555);
        state.balances.insert(AtomicBalanceKey { asset_id: asset_a, owner_id: owner_b }, 777);
        state.balances.insert(AtomicBalanceKey { asset_id: asset_b, owner_id: owner_a }, 999);
        state.balances.insert(AtomicBalanceKey { asset_id: asset_b, owner_id: owner_b }, 0);
        state.next_nonces.insert(AtomicNonceKey::owner(owner_a), 4);
        state.next_nonces.insert(AtomicNonceKey::asset(owner_a, asset_a), 6);
        state.next_nonces.insert(AtomicNonceKey::asset(owner_b, asset_b), 1);
        state.anchor_counts.insert(owner_a, 3);
        state.anchor_counts.insert(owner_b, 5);

        let audit_root = state.p2p_token_audit_hash().expect("full state is auditable");
        assert_eq!(faster_hex::hex_string(&audit_root), "d61e226e9ea824488ff7462e334115a9e5293b4576d58813056dfcc1159f9f92");

        let mut anchor_changed = state.clone();
        anchor_changed.anchor_counts.insert(owner_a, 99);
        assert_eq!(anchor_changed.p2p_token_audit_hash(), Some(audit_root));

        let mut metadata_changed = state.clone();
        metadata_changed.assets.get_mut(&asset_a).expect("asset A").metadata = b"changed-but-uncommitted".to_vec();
        metadata_changed.assets.get_mut(&asset_a).expect("asset A").name = b"OtherName".to_vec();
        metadata_changed.assets.get_mut(&asset_a).expect("asset A").decimals = 4;
        assert_eq!(metadata_changed.p2p_token_audit_hash(), Some(audit_root));

        let mut committed_changed = state;
        committed_changed.assets.get_mut(&asset_b).expect("asset B").total_supply += 1;
        assert_ne!(committed_changed.p2p_token_audit_hash(), Some(audit_root));
    }

    #[test]
    fn canonical_atomic_state_hash_is_order_independent() {
        let asset_a = [0xA0; 32];
        let asset_b = [0xB0; 32];
        let mut left = AtomicConsensusState::default();
        let mut right = AtomicConsensusState::default();

        let standard_asset = AtomicAssetState {
            creator_owner_id: owner(0),
            asset_class: AtomicAssetClass::Standard,
            token_version: ATOMIC_CURRENT_TOKEN_VERSION,
            mint_authority_owner_id: owner(1),
            decimals: 8,
            supply_mode: AtomicSupplyMode::Capped,
            max_supply: 1_000,
            total_supply: 11,
            name: b"Order Token".to_vec(),
            symbol: b"ORD".to_vec(),
            metadata: Vec::new(),
            platform_tag: Vec::new(),
            created_block_hash: None,
            created_daa_score: None,
            created_at: None,
            liquidity: None,
        };
        let fee_recipient_payload = vec![4; 32];
        let fee_recipient_owner =
            atomic_owner_id_from_address_components(0, &fee_recipient_payload).expect("test recipient owner should derive");
        let liquidity_asset = AtomicAssetState {
            creator_owner_id: owner(2),
            asset_class: AtomicAssetClass::Liquidity,
            token_version: ATOMIC_CURRENT_TOKEN_VERSION,
            mint_authority_owner_id: [0; 32],
            decimals: 0,
            supply_mode: AtomicSupplyMode::Capped,
            max_supply: 10_000,
            total_supply: 500,
            name: b"Order LP".to_vec(),
            symbol: b"OLP".to_vec(),
            metadata: Vec::new(),
            platform_tag: Vec::new(),
            created_block_hash: None,
            created_daa_score: None,
            created_at: None,
            liquidity: Some(AtomicLiquidityPoolState {
                pool_nonce: 7,
                curve_version: ATOMIC_CURRENT_LIQUIDITY_CURVE_VERSION,
                curve_mode: ATOMIC_DEFAULT_LIQUIDITY_CURVE_MODE,
                individual_virtual_cpay_reserves_sompi: 0,
                individual_virtual_token_multiplier_bps: 0,
                real_cpay_reserves_sompi: 250,
                real_token_reserves: 9_500,
                virtual_cpay_reserves_sompi: 1_000_000_000_000,
                virtual_token_reserves: 1_300_000,
                unclaimed_fee_total_sompi: 3,
                fee_bps: 100,
                fee_recipients: vec![AtomicLiquidityFeeRecipientState {
                    owner_id: fee_recipient_owner,
                    address_version: 0,
                    address_payload: fee_recipient_payload,
                    unclaimed_sompi: 3,
                }],
                vault_outpoint: TransactionOutpoint::new(hash(9), 1),
                vault_value_sompi: 253,
                unlock_target_sompi: 0,
                unlocked: true,
            }),
        };

        left.next_nonces.insert(AtomicNonceKey::owner(owner(5)), 2);
        left.next_nonces.insert(AtomicNonceKey::asset(owner(4), asset_a), 9);
        left.assets.insert(asset_b, liquidity_asset.clone());
        left.assets.insert(asset_a, standard_asset.clone());
        left.balances.insert(AtomicBalanceKey { asset_id: asset_b, owner_id: owner(8) }, 500);
        left.balances.insert(AtomicBalanceKey { asset_id: asset_a, owner_id: owner(7) }, 11);
        left.anchor_counts.insert(owner(6), 1);
        left.rebuild_liquidity_vault_outpoint_index();

        right.anchor_counts.insert(owner(6), 1);
        right.balances.insert(AtomicBalanceKey { asset_id: asset_a, owner_id: owner(7) }, 11);
        right.balances.insert(AtomicBalanceKey { asset_id: asset_b, owner_id: owner(8) }, 500);
        right.assets.insert(asset_a, standard_asset);
        right.assets.insert(asset_b, liquidity_asset);
        right.next_nonces.insert(AtomicNonceKey::asset(owner(4), asset_a), 9);
        right.next_nonces.insert(AtomicNonceKey::owner(owner(5)), 2);
        right.rebuild_liquidity_vault_outpoint_index();

        left.validate_normalized().expect("left state should be normalized");
        right.validate_normalized().expect("right state should be normalized");
        assert_eq!(left.canonical_hash(), right.canonical_hash());
    }

    #[test]
    fn atomic_consensus_state_tracks_block_delta_from_mutators() {
        let asset_id = [0xAB; 32];
        let owner_id = owner(0xCD);
        let nonce_key = AtomicNonceKey::owner(owner_id);
        let balance_key = AtomicBalanceKey { asset_id, owner_id };
        let asset = AtomicAssetState {
            creator_owner_id: owner_id,
            asset_class: AtomicAssetClass::Standard,
            token_version: ATOMIC_CURRENT_TOKEN_VERSION,
            mint_authority_owner_id: owner_id,
            decimals: 8,
            supply_mode: AtomicSupplyMode::Capped,
            max_supply: 1_000,
            total_supply: 10,
            name: b"Delta Token".to_vec(),
            symbol: b"DLT".to_vec(),
            metadata: Vec::new(),
            platform_tag: Vec::new(),
            created_block_hash: None,
            created_daa_score: None,
            created_at: None,
            liquidity: None,
        };

        let mut state = AtomicConsensusState::default();
        state.begin_delta_tracking();
        state.set_next_nonce(nonce_key, 2);
        state.set_asset(asset_id, asset).expect("asset insert");
        state.set_balance(balance_key, 10);
        state.set_balance(balance_key, 7);
        state.set_anchor_count(owner_id, 1);

        let delta = state.take_delta();
        assert_eq!(delta.nonce_changes.len(), 1);
        assert_eq!(delta.nonce_changes[0].old_value, None);
        assert_eq!(delta.nonce_changes[0].new_value, Some(2));
        assert_eq!(delta.asset_changes.len(), 1);
        assert_eq!(delta.asset_changes[0].old_value, None);
        assert!(delta.asset_changes[0].new_value.is_some());
        assert_eq!(delta.balance_changes.len(), 1);
        assert_eq!(delta.balance_changes[0].old_value, None);
        assert_eq!(delta.balance_changes[0].new_value, Some(7));
        assert_eq!(delta.anchor_count_changes.len(), 1);
        assert_eq!(delta.anchor_count_changes[0].old_value, None);
        assert_eq!(delta.anchor_count_changes[0].new_value, Some(1));
    }

    #[test]
    fn atomic_consensus_state_delta_preserves_prior_change_when_later_set_is_noop() {
        let owner_id = owner(0xCE);
        let mut state = AtomicConsensusState::default();
        state.begin_delta_tracking();
        state.set_anchor_count(owner_id, 1);
        state.set_anchor_count(owner_id, 1);

        let delta = state.take_delta();
        assert_eq!(delta.anchor_count_changes.len(), 1);
        assert_eq!(delta.anchor_count_changes[0].old_value, None);
        assert_eq!(delta.anchor_count_changes[0].new_value, Some(1));

        let mut replayed = AtomicConsensusState::default();
        replayed.apply_delta_forward(&delta).expect("forward delta applies");
        assert_eq!(replayed.canonical_hash(), state.canonical_hash());
    }

    #[test]
    fn atomic_consensus_state_delta_replays_forward_and_back() {
        let asset_id = [0xBC; 32];
        let owner_id = owner(0xDE);
        let nonce_key = AtomicNonceKey::owner(owner_id);
        let balance_key = AtomicBalanceKey { asset_id, owner_id };
        let asset = AtomicAssetState {
            creator_owner_id: owner_id,
            asset_class: AtomicAssetClass::Standard,
            token_version: ATOMIC_CURRENT_TOKEN_VERSION,
            mint_authority_owner_id: owner_id,
            decimals: 8,
            supply_mode: AtomicSupplyMode::Capped,
            max_supply: 1_000,
            total_supply: 25,
            name: b"Replay Token".to_vec(),
            symbol: b"RPL".to_vec(),
            metadata: Vec::new(),
            platform_tag: Vec::new(),
            created_block_hash: None,
            created_daa_score: None,
            created_at: None,
            liquidity: None,
        };

        let base = AtomicConsensusState::default();
        let base_hash = base.canonical_hash();
        let mut changed = base.clone();
        changed.begin_delta_tracking();
        changed.set_next_nonce(nonce_key, 2);
        changed.set_asset(asset_id, asset).expect("asset insert");
        changed.set_balance(balance_key, 25);
        changed.set_anchor_count(owner_id, 1);
        let delta = changed.take_delta();
        let changed_hash = changed.canonical_hash();

        let mut replayed = base.clone();
        replayed.apply_delta_forward(&delta).expect("forward delta applies");
        assert_eq!(replayed.canonical_hash(), changed_hash);
        assert_eq!(replayed.balance(&balance_key), 25);

        replayed.apply_delta_rollback(&delta).expect("rollback delta applies");
        assert_eq!(replayed.canonical_hash(), base_hash);
        assert!(replayed.assets.is_empty());
        assert!(replayed.balances.is_empty());
        assert!(replayed.next_nonces.is_empty());
        assert!(replayed.anchor_counts.is_empty());
    }

    #[test]
    fn atomic_consensus_state_persists_current_overlay_and_reads_lazily() {
        let (_lifetime, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbAtomicStateStore::new(db.clone(), CachePolicy::Empty);
        let asset_id = [0xD0; 32];
        let owner_id = owner(0xD1);
        let nonce_key = AtomicNonceKey::asset(owner_id, asset_id);
        let balance_key = AtomicBalanceKey { asset_id, owner_id };
        let vault_outpoint = TransactionOutpoint::new(hash(0xDA), 2);
        let asset = AtomicAssetState {
            creator_owner_id: owner_id,
            asset_class: AtomicAssetClass::Liquidity,
            token_version: ATOMIC_CURRENT_TOKEN_VERSION,
            mint_authority_owner_id: [0; 32],
            decimals: 0,
            supply_mode: AtomicSupplyMode::Capped,
            max_supply: 1_000,
            total_supply: 100,
            name: b"Stored LP".to_vec(),
            symbol: b"SLP".to_vec(),
            metadata: Vec::new(),
            platform_tag: Vec::new(),
            created_block_hash: None,
            created_daa_score: None,
            created_at: None,
            liquidity: Some(AtomicLiquidityPoolState {
                pool_nonce: 3,
                curve_version: ATOMIC_CURRENT_LIQUIDITY_CURVE_VERSION,
                curve_mode: ATOMIC_DEFAULT_LIQUIDITY_CURVE_MODE,
                individual_virtual_cpay_reserves_sompi: 0,
                individual_virtual_token_multiplier_bps: 0,
                real_cpay_reserves_sompi: 50,
                real_token_reserves: 900,
                virtual_cpay_reserves_sompi: 1_000_000_000_000,
                virtual_token_reserves: 1_300_000,
                unclaimed_fee_total_sompi: 0,
                fee_bps: 0,
                fee_recipients: Vec::new(),
                vault_outpoint,
                vault_value_sompi: 50,
                unlock_target_sompi: 0,
                unlocked: true,
            }),
        };

        let mut state = store.attach_virtual_state(&AtomicConsensusState::default());
        state.set_next_nonce(nonce_key, 9);
        state.set_asset(asset_id, asset.clone()).expect("asset insert");
        state.set_balance(balance_key, 100);
        state.set_anchor_count(owner_id, 1);

        let mut batch = WriteBatch::default();
        store.write_current_overlay_batch(&mut batch, &state).expect("current overlay write");
        db.write(batch).expect("commit current overlay");

        let compact = state.as_virtual_root_state();
        assert!(compact.next_nonces.is_empty());
        assert!(compact.assets.is_empty());
        assert!(compact.balances.is_empty());
        assert!(compact.anchor_counts.is_empty());

        let lazy = store.attach_virtual_state(&compact);
        assert_eq!(lazy.next_nonce(&nonce_key), 9);
        assert_eq!(lazy.cloned_asset(&asset_id), Some(asset));
        assert_eq!(lazy.balance(&balance_key), 100);
        assert_eq!(lazy.anchor_count(&owner_id), 1);
        assert_eq!(lazy.liquidity_asset_by_vault_outpoint(vault_outpoint).expect("vault lookup"), Some(asset_id));
        assert_eq!(store.read_current_root().expect("current root"), Some(compact.root_accumulator()));
    }

    #[test]
    fn atomic_consensus_state_current_overlay_removes_deleted_keys() {
        let (_lifetime, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbAtomicStateStore::new(db.clone(), CachePolicy::Empty);
        let asset_id = [0xE0; 32];
        let owner_id = owner(0xE1);
        let balance_key = AtomicBalanceKey { asset_id, owner_id };
        let asset = AtomicAssetState {
            creator_owner_id: owner_id,
            asset_class: AtomicAssetClass::Standard,
            token_version: ATOMIC_CURRENT_TOKEN_VERSION,
            mint_authority_owner_id: owner_id,
            decimals: 8,
            supply_mode: AtomicSupplyMode::Capped,
            max_supply: 1_000,
            total_supply: 77,
            name: b"Delete Token".to_vec(),
            symbol: b"DEL".to_vec(),
            metadata: Vec::new(),
            platform_tag: Vec::new(),
            created_block_hash: None,
            created_daa_score: None,
            created_at: None,
            liquidity: None,
        };

        let mut state = store.attach_virtual_state(&AtomicConsensusState::default());
        state.set_asset(asset_id, asset).expect("asset insert");
        state.set_balance(balance_key, 77);
        let mut batch = WriteBatch::default();
        store.write_current_overlay_batch(&mut batch, &state).expect("initial overlay write");
        db.write(batch).expect("commit initial overlay");

        let mut lazy = store.attach_virtual_state(&state.as_virtual_root_state());
        lazy.set_balance(balance_key, 0);
        let mut batch = WriteBatch::default();
        store.write_current_overlay_batch(&mut batch, &lazy).expect("delete overlay write");
        db.write(batch).expect("commit delete overlay");

        let lazy_after_delete = store.attach_virtual_state(&lazy.as_virtual_root_state());
        assert!(!lazy_after_delete.has_balance(&balance_key));
        assert_eq!(lazy_after_delete.balance(&balance_key), 0);
        assert_eq!(store.read_current_balance(&balance_key).expect("balance read"), None);
    }

    #[test]
    fn atomic_state_store_persists_only_root_and_delta_records() {
        let (_lifetime, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbAtomicStateStore::new(db.clone(), CachePolicy::Empty);
        let block_hash = hash(0x44);
        let state_hash = [0x55; 32];
        let delta = Arc::new(AtomicConsensusStateDelta {
            nonce_changes: vec![AtomicNonceChange { key: AtomicNonceKey::owner(owner(0x56)), old_value: None, new_value: Some(2) }],
            asset_changes: Vec::new(),
            balance_changes: Vec::new(),
            anchor_count_changes: Vec::new(),
        });

        let mut batch = WriteBatch::default();
        store.insert_batch_with_delta(&mut batch, block_hash, state_hash, delta.clone()).expect("root/delta insert");
        db.write(batch).expect("commit root/delta");

        let root = store.get_root_record(block_hash).expect("root record");
        assert_eq!(root.state_hash, state_hash);
        assert_eq!(root.nonce_changes, 1);
        let stored_delta = store.get_delta(block_hash).expect("delta record");
        assert_eq!(stored_delta.as_ref(), delta.as_ref());

        let mut duplicate_batch = WriteBatch::default();
        assert!(matches!(
            store.insert_root_batch(&mut duplicate_batch, block_hash, [0x66; 32]),
            Err(StoreError::HashAlreadyExists(hash)) if hash == block_hash
        ));
    }

    #[test]
    fn atomic_state_store_deletes_records_above_target_daa_and_orphans() {
        let (_lifetime, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbAtomicStateStore::new(db.clone(), CachePolicy::Empty);
        let keep_hash = hash(0x10);
        let above_hash = hash(0x20);
        let orphan_hash = hash(0x30);

        let mut batch = WriteBatch::default();
        store.insert_root_batch(&mut batch, keep_hash, [0x11; 32]).expect("keep root insert");
        store.insert_root_batch(&mut batch, above_hash, [0x22; 32]).expect("above root insert");
        store.insert_root_batch(&mut batch, orphan_hash, [0x33; 32]).expect("orphan root insert");
        db.write(batch).expect("commit roots");

        let mut cleanup_batch = WriteBatch::default();
        let (deleted_above, deleted_orphans) = store
            .delete_records_above_daa_batch(
                &mut cleanup_batch,
                |hash| {
                    if hash == keep_hash {
                        Ok(Some(10))
                    } else if hash == above_hash {
                        Ok(Some(11))
                    } else {
                        Ok(None)
                    }
                },
                10,
            )
            .expect("cleanup scan");
        db.write(cleanup_batch).expect("commit cleanup");

        assert_eq!((deleted_above, deleted_orphans), (1, 1));
        assert!(store.get_root_record(keep_hash).is_ok());
        assert!(matches!(store.get_root_record(above_hash), Err(StoreError::KeyNotFound(_))));
        assert!(matches!(store.get_root_record(orphan_hash), Err(StoreError::KeyNotFound(_))));
    }

    #[test]
    fn atomic_consensus_state_interop_vector_matches_fixture() {
        let fixture_path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("docs").join("atomic_consensus_state_root_v2.json");
        let actual = atomic_interop_vector_json();
        if std::env::var_os("CRYPTIX_WRITE_ATOMIC_INTEROP_VECTOR").is_some() {
            let json = serde_json::to_string_pretty(&actual).expect("serialize interop vector");
            std::fs::write(&fixture_path, format!("{json}\n")).expect("write interop vector fixture");
            return;
        }

        let expected_bytes = std::fs::read(&fixture_path).expect("read interop vector fixture");
        let expected: serde_json::Value = serde_json::from_slice(&expected_bytes).expect("parse interop vector fixture");
        assert_eq!(actual, expected);
    }
}
