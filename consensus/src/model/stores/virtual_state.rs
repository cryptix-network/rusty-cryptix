use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;

use arc_swap::ArcSwap;
use cryptix_consensus_core::api::stats::VirtualStateStats;
use cryptix_consensus_core::{
    block::VirtualStateApproxId,
    coinbase::BlockRewardData,
    config::genesis::GenesisBlock,
    tx::{TransactionId, TransactionOutpoint},
    utxo::utxo_diff::UtxoDiff,
    BlockHashMap, BlockHashSet, HashMapCustomHasher,
};
use cryptix_database::prelude::{BatchDbWriter, CachedDbItem, DbKey, DirectDbWriter, StoreResultExtensions};
use cryptix_database::prelude::{CachePolicy, StoreResult};
use cryptix_database::prelude::{StoreError, DB};
use cryptix_database::registry::DatabaseStorePrefixes;
use cryptix_hashes::Hash;
use cryptix_muhash::MuHash;
use rocksdb::WriteBatch;
use serde::{Deserialize, Serialize};

use super::atomic_state::{AtomicAssetState, AtomicBalanceKey, AtomicConsensusState, AtomicConsensusStateDelta, AtomicNonceKey};
use super::ghostdag::GhostdagData;
use super::utxo_set::DbUtxoSetStore;

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct VirtualState {
    pub parents: Vec<Hash>,
    pub ghostdag_data: GhostdagData,
    pub daa_score: u64,
    pub bits: u32,
    pub past_median_time: u64,
    pub multiset: MuHash,
    pub utxo_diff: UtxoDiff, // This is the UTXO diff from the selected tip to the virtual. i.e., if this diff is applied on the past UTXO of the selected tip, we'll get the virtual UTXO set.
    pub accepted_tx_ids: Vec<TransactionId>, // TODO: consider saving `accepted_id_merkle_root` directly
    pub mergeset_rewards: BlockHashMap<BlockRewardData>,
    pub mergeset_non_daa: BlockHashSet,
    #[serde(default)]
    pub atomic_diff: AtomicConsensusStateDelta,
    #[serde(default)]
    pub atomic_state: AtomicConsensusState,
}

#[derive(Clone, Serialize, Deserialize, Default)]
struct LegacyAtomicConsensusState {
    #[serde(default)]
    next_nonces: HashMap<AtomicNonceKey, u64>,
    #[serde(default)]
    assets: HashMap<[u8; 32], AtomicAssetState>,
    #[serde(default)]
    balances: HashMap<AtomicBalanceKey, u128>,
    #[serde(default)]
    anchor_counts: HashMap<[u8; 32], u64>,
    #[serde(default)]
    liquidity_vault_outpoints: HashMap<TransactionOutpoint, [u8; 32]>,
}

impl From<LegacyAtomicConsensusState> for AtomicConsensusState {
    fn from(value: LegacyAtomicConsensusState) -> Self {
        let mut state = AtomicConsensusState::default();
        state.next_nonces = value.next_nonces;
        state.assets = value.assets;
        state.balances = value.balances;
        state.anchor_counts = value.anchor_counts;
        state.liquidity_vault_outpoints = value.liquidity_vault_outpoints;
        state.rebuild_liquidity_vault_outpoint_index();
        state
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
struct LegacyVirtualStateWithAtomic {
    parents: Vec<Hash>,
    ghostdag_data: GhostdagData,
    daa_score: u64,
    bits: u32,
    past_median_time: u64,
    multiset: MuHash,
    utxo_diff: UtxoDiff,
    accepted_tx_ids: Vec<TransactionId>,
    mergeset_rewards: BlockHashMap<BlockRewardData>,
    mergeset_non_daa: BlockHashSet,
    #[serde(default)]
    atomic_state: LegacyAtomicConsensusState,
}

impl From<LegacyVirtualStateWithAtomic> for VirtualState {
    fn from(value: LegacyVirtualStateWithAtomic) -> Self {
        Self {
            parents: value.parents,
            ghostdag_data: value.ghostdag_data,
            daa_score: value.daa_score,
            bits: value.bits,
            past_median_time: value.past_median_time,
            multiset: value.multiset,
            utxo_diff: value.utxo_diff,
            accepted_tx_ids: value.accepted_tx_ids,
            mergeset_rewards: value.mergeset_rewards,
            mergeset_non_daa: value.mergeset_non_daa,
            atomic_diff: AtomicConsensusStateDelta::default(),
            atomic_state: value.atomic_state.into(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
struct LegacyVirtualStateWithoutAtomic {
    parents: Vec<Hash>,
    ghostdag_data: GhostdagData,
    daa_score: u64,
    bits: u32,
    past_median_time: u64,
    multiset: MuHash,
    utxo_diff: UtxoDiff,
    accepted_tx_ids: Vec<TransactionId>,
    mergeset_rewards: BlockHashMap<BlockRewardData>,
    mergeset_non_daa: BlockHashSet,
}

impl From<LegacyVirtualStateWithoutAtomic> for VirtualState {
    fn from(value: LegacyVirtualStateWithoutAtomic) -> Self {
        Self {
            parents: value.parents,
            ghostdag_data: value.ghostdag_data,
            daa_score: value.daa_score,
            bits: value.bits,
            past_median_time: value.past_median_time,
            multiset: value.multiset,
            utxo_diff: value.utxo_diff,
            accepted_tx_ids: value.accepted_tx_ids,
            mergeset_rewards: value.mergeset_rewards,
            mergeset_non_daa: value.mergeset_non_daa,
            atomic_diff: AtomicConsensusStateDelta::default(),
            atomic_state: AtomicConsensusState::default(),
        }
    }
}

impl VirtualState {
    pub fn new(
        parents: Vec<Hash>,
        daa_score: u64,
        bits: u32,
        past_median_time: u64,
        multiset: MuHash,
        utxo_diff: UtxoDiff,
        accepted_tx_ids: Vec<TransactionId>,
        mergeset_rewards: BlockHashMap<BlockRewardData>,
        mergeset_non_daa: BlockHashSet,
        atomic_diff: AtomicConsensusStateDelta,
        atomic_state: AtomicConsensusState,
        ghostdag_data: GhostdagData,
    ) -> Self {
        Self {
            parents,
            ghostdag_data,
            daa_score,
            bits,
            past_median_time,
            multiset,
            utxo_diff,
            accepted_tx_ids,
            mergeset_rewards,
            mergeset_non_daa,
            atomic_diff,
            atomic_state,
        }
    }

    pub fn from_genesis(genesis: &GenesisBlock, ghostdag_data: GhostdagData) -> Self {
        Self {
            parents: vec![genesis.hash],
            ghostdag_data,
            daa_score: genesis.daa_score,
            bits: genesis.bits,
            past_median_time: genesis.timestamp,
            multiset: MuHash::new(),
            utxo_diff: UtxoDiff::default(), // Virtual diff is initially empty since genesis receives no reward
            accepted_tx_ids: genesis.build_genesis_transactions().into_iter().map(|tx| tx.id()).collect(),
            mergeset_rewards: BlockHashMap::new(),
            mergeset_non_daa: BlockHashSet::from_iter(std::iter::once(genesis.hash)),
            atomic_diff: AtomicConsensusStateDelta::default(),
            atomic_state: AtomicConsensusState::default(),
        }
    }

    pub fn to_virtual_state_approx_id(&self) -> VirtualStateApproxId {
        VirtualStateApproxId::new(self.daa_score, self.ghostdag_data.blue_work, self.ghostdag_data.selected_parent)
    }
}

impl From<&VirtualState> for VirtualStateStats {
    fn from(state: &VirtualState) -> Self {
        Self {
            num_parents: state.parents.len() as u32,
            daa_score: state.daa_score,
            bits: state.bits,
            past_median_time: state.past_median_time,
        }
    }
}

/// Represents the "last known good" virtual state. To be used by any logic which does not want to wait
/// for a possible virtual state write to complete but can rather settle with the last known state
#[derive(Clone, Default)]
pub struct LkgVirtualState {
    inner: Arc<ArcSwap<VirtualState>>,
}

/// Guard for accessing the last known good virtual state (lock-free)
/// It's a simple newtype over arc_swap::Guard just to avoid explicit dependency
pub struct LkgVirtualStateGuard(arc_swap::Guard<Arc<VirtualState>>);

impl Deref for LkgVirtualStateGuard {
    type Target = Arc<VirtualState>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl LkgVirtualState {
    /// Provides a temporary borrow to the last known good virtual state.
    pub fn load(&self) -> LkgVirtualStateGuard {
        LkgVirtualStateGuard(self.inner.load())
    }

    /// Loads the last known good virtual state.
    pub fn load_full(&self) -> Arc<VirtualState> {
        self.inner.load_full()
    }

    // Kept private in order to make sure it is only updated by DbVirtualStateStore
    fn store(&self, virtual_state: Arc<VirtualState>) {
        self.inner.store(virtual_state)
    }
}

/// Used in order to group virtual related stores under a single lock
pub struct VirtualStores {
    pub state: DbVirtualStateStore,
    pub utxo_set: DbUtxoSetStore,
}

impl VirtualStores {
    pub fn new(db: Arc<DB>, lkg_virtual_state: LkgVirtualState, utxoset_cache_policy: CachePolicy) -> Self {
        Self {
            state: DbVirtualStateStore::new(db.clone(), lkg_virtual_state),
            utxo_set: DbUtxoSetStore::new(db, utxoset_cache_policy, DatabaseStorePrefixes::VirtualUtxoset.into()),
        }
    }
}

/// Reader API for `VirtualStateStore`.
pub trait VirtualStateStoreReader {
    fn get(&self) -> StoreResult<Arc<VirtualState>>;
}

pub trait VirtualStateStore: VirtualStateStoreReader {
    fn set(&mut self, state: Arc<VirtualState>) -> StoreResult<()>;
}

/// A DB + cache implementation of `VirtualStateStore` trait
#[derive(Clone)]
pub struct DbVirtualStateStore {
    db: Arc<DB>,
    key: Vec<u8>,
    access: CachedDbItem<Arc<VirtualState>>,
    /// The "last known good" virtual state
    lkg_virtual_state: LkgVirtualState,
}

impl DbVirtualStateStore {
    pub fn new(db: Arc<DB>, lkg_virtual_state: LkgVirtualState) -> Self {
        let key: Vec<u8> = DatabaseStorePrefixes::VirtualState.into();
        let access = CachedDbItem::new(db.clone(), key.clone());
        let store = Self { db, key, access, lkg_virtual_state };
        // Init the LKG cache from DB store data
        store.lkg_virtual_state.store(store.read_compatible().unwrap_option().unwrap_or_default());
        store
    }

    pub fn clone_with_new_cache(&self) -> Self {
        Self::new(self.db.clone(), self.lkg_virtual_state.clone())
    }

    fn persist_current_format(&self, state: &Arc<VirtualState>) -> StoreResult<()> {
        let mut access = self.access.clone();
        access.write(DirectDbWriter::new(&self.db), state)
    }

    fn legacy_atomic_state_is_empty(state: &AtomicConsensusState) -> bool {
        state.next_nonces.is_empty()
            && state.assets.is_empty()
            && state.balances.is_empty()
            && state.anchor_counts.is_empty()
            && state.liquidity_vault_outpoints.is_empty()
    }

    fn read_legacy_and_maybe_migrate(&self, current_error: Box<bincode::ErrorKind>) -> StoreResult<Arc<VirtualState>> {
        let Some(slice) = self.db.get_pinned(&self.key)? else {
            return Err(StoreError::KeyNotFound(DbKey::prefix_only(&self.key)));
        };
        let bytes = slice.as_ref();

        if let Ok(legacy) = bincode::deserialize::<LegacyVirtualStateWithAtomic>(bytes) {
            let state = Arc::new(VirtualState::from(legacy));
            if Self::legacy_atomic_state_is_empty(&state.atomic_state) {
                self.persist_current_format(&state)?;
            }
            return Ok(state);
        }

        if let Ok(legacy) = bincode::deserialize::<LegacyVirtualStateWithoutAtomic>(bytes) {
            let state = Arc::new(VirtualState::from(legacy));
            self.persist_current_format(&state)?;
            return Ok(state);
        }

        Err(StoreError::DeserializationError(current_error))
    }

    fn read_compatible(&self) -> StoreResult<Arc<VirtualState>> {
        match self.access.read() {
            Ok(state) => Ok(state),
            Err(StoreError::DeserializationError(err)) => self.read_legacy_and_maybe_migrate(err),
            Err(err) => Err(err),
        }
    }

    pub fn is_initialized(&self) -> StoreResult<bool> {
        match self.read_compatible() {
            Ok(_) => Ok(true),
            Err(StoreError::KeyNotFound(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    pub fn set_batch(&mut self, batch: &mut WriteBatch, state: Arc<VirtualState>) -> StoreResult<()> {
        self.lkg_virtual_state.store(state.clone()); // Keep the LKG cache up-to-date
        self.access.write(BatchDbWriter::new(batch), &state)
    }
}

impl VirtualStateStoreReader for DbVirtualStateStore {
    fn get(&self) -> StoreResult<Arc<VirtualState>> {
        self.read_compatible()
    }
}

impl VirtualStateStore for DbVirtualStateStore {
    fn set(&mut self, state: Arc<VirtualState>) -> StoreResult<()> {
        self.lkg_virtual_state.store(state.clone()); // Keep the LKG cache up-to-date
        self.access.write(DirectDbWriter::new(&self.db), &state)
    }
}

#[cfg(test)]
mod tests {
    use super::super::atomic_state::DbAtomicStateStore;
    use super::*;
    use cryptix_database::{create_temp_db, prelude::ConnBuilder};

    fn legacy_without_atomic(daa_score: u64) -> LegacyVirtualStateWithoutAtomic {
        LegacyVirtualStateWithoutAtomic {
            parents: vec![Hash::from_bytes([1; 32])],
            ghostdag_data: GhostdagData::default(),
            daa_score,
            bits: 7,
            past_median_time: 99,
            multiset: MuHash::new(),
            utxo_diff: UtxoDiff::default(),
            accepted_tx_ids: Vec::new(),
            mergeset_rewards: BlockHashMap::default(),
            mergeset_non_daa: BlockHashSet::default(),
        }
    }

    #[test]
    fn legacy_virtual_state_without_atomic_is_migrated_on_read() {
        let (_lifetime, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let key: Vec<u8> = DatabaseStorePrefixes::VirtualState.into();
        db.put(&key, bincode::serialize(&legacy_without_atomic(42)).unwrap()).unwrap();

        let store = DbVirtualStateStore::new(db.clone(), LkgVirtualState::default());
        let state = store.get().unwrap();
        assert_eq!(state.daa_score, 42);
        assert!(state.atomic_diff.is_empty());
        assert!(state.atomic_state.next_nonces.is_empty());

        let raw = db.get_pinned(&key).unwrap().expect("migrated virtual state must be persisted");
        let migrated: Arc<VirtualState> = bincode::deserialize(raw.as_ref()).unwrap();
        assert_eq!(migrated.daa_score, 42);
    }

    #[test]
    fn legacy_virtual_state_with_atomic_maps_can_bootstrap_v2_current_store() {
        let (_lifetime, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let key: Vec<u8> = DatabaseStorePrefixes::VirtualState.into();
        let nonce_key = AtomicNonceKey::owner([0x42; 32]);
        let mut atomic_state = LegacyAtomicConsensusState::default();
        atomic_state.next_nonces.insert(nonce_key, 2);
        let mut legacy = LegacyVirtualStateWithAtomic::from(legacy_without_atomic(77));
        legacy.atomic_state = atomic_state;
        db.put(&key, bincode::serialize(&legacy).unwrap()).unwrap();

        let virtual_store = DbVirtualStateStore::new(db.clone(), LkgVirtualState::default());
        let state = virtual_store.get().unwrap();
        assert_eq!(state.daa_score, 77);
        assert_eq!(state.atomic_state.next_nonce(&nonce_key), 2);

        let atomic_store = DbAtomicStateStore::new(db, CachePolicy::Empty);
        let attached = atomic_store.attach_virtual_state(&state.atomic_state);
        assert_eq!(attached.next_nonce(&nonce_key), 2);
        assert_eq!(atomic_store.read_current_nonce(&nonce_key).unwrap(), Some(2));
    }

    impl From<LegacyVirtualStateWithoutAtomic> for LegacyVirtualStateWithAtomic {
        fn from(value: LegacyVirtualStateWithoutAtomic) -> Self {
            Self {
                parents: value.parents,
                ghostdag_data: value.ghostdag_data,
                daa_score: value.daa_score,
                bits: value.bits,
                past_median_time: value.past_median_time,
                multiset: value.multiset,
                utxo_diff: value.utxo_diff,
                accepted_tx_ids: value.accepted_tx_ids,
                mergeset_rewards: value.mergeset_rewards,
                mergeset_non_daa: value.mergeset_non_daa,
                atomic_state: LegacyAtomicConsensusState::default(),
            }
        }
    }
}
