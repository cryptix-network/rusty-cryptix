use cryptix_consensus_core::tx::TransactionOutpoint;
use cryptix_consensus_core::BlockHasher;
use cryptix_database::prelude::CachePolicy;
use cryptix_database::prelude::StoreError;
use cryptix_database::prelude::DB;
use cryptix_database::prelude::{BatchDbWriter, CachedDbAccess, DirectDbWriter};
use cryptix_database::registry::DatabaseStorePrefixes;
use cryptix_hashes::Hash;
use cryptix_utils::mem_size::MemSizeEstimator;
use rocksdb::WriteBatch;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::mem::size_of;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AtomicBalanceKey {
    pub asset_id: [u8; 32],
    pub owner_id: [u8; 32],
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
    pub remaining_pool_supply: u128,
    pub curve_reserve_sompi: u64,
    pub unclaimed_fee_total_sompi: u64,
    pub fee_bps: u16,
    pub fee_recipients: Vec<AtomicLiquidityFeeRecipientState>,
    pub vault_outpoint: TransactionOutpoint,
    pub vault_value_sompi: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomicAssetState {
    #[serde(default)]
    pub asset_class: AtomicAssetClass,
    pub mint_authority_owner_id: [u8; 32],
    pub supply_mode: AtomicSupplyMode,
    pub max_supply: u128,
    pub total_supply: u128,
    #[serde(default)]
    pub liquidity: Option<AtomicLiquidityPoolState>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AtomicConsensusState {
    #[serde(default)]
    pub next_nonces: HashMap<[u8; 32], u64>,
    #[serde(default)]
    pub assets: HashMap<[u8; 32], AtomicAssetState>,
    #[serde(default)]
    pub balances: HashMap<AtomicBalanceKey, u128>,
    #[serde(default)]
    pub anchor_counts: HashMap<[u8; 32], u64>,
    #[serde(default)]
    pub liquidity_vault_outpoints: HashMap<TransactionOutpoint, [u8; 32]>,
}

impl AtomicConsensusState {
    pub fn rebuild_liquidity_vault_outpoint_index(&mut self) {
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
}

pub trait AtomicStateStoreReader {
    fn get(&self, hash: Hash) -> Result<Arc<AtomicConsensusState>, StoreError>;
}

pub trait AtomicStateStore: AtomicStateStoreReader {
    fn insert(&self, hash: Hash, atomic_state: Arc<AtomicConsensusState>) -> Result<(), StoreError>;
    fn delete(&self, hash: Hash) -> Result<(), StoreError>;
}

/// Simple wrapper for implementing `MemSizeEstimator`
#[derive(Clone, Serialize, Deserialize)]
struct AtomicConsensusStateEntry(Arc<AtomicConsensusState>);

impl MemSizeEstimator for AtomicConsensusStateEntry {
    fn estimate_mem_bytes(&self) -> usize {
        let state = self.0.as_ref();
        let liquidity_heap: usize = state
            .assets
            .values()
            .map(|asset| {
                asset
                    .liquidity
                    .as_ref()
                    .map(|pool| {
                        pool.fee_recipients
                            .iter()
                            .map(|recipient| size_of::<AtomicLiquidityFeeRecipientState>() + recipient.address_payload.len())
                            .sum::<usize>()
                    })
                    .unwrap_or(0)
            })
            .sum();
        size_of::<Self>()
            + state.next_nonces.len() * (size_of::<[u8; 32]>() + size_of::<u64>())
            + state.assets.len() * (size_of::<[u8; 32]>() + size_of::<AtomicAssetState>())
            + state.balances.len() * (size_of::<AtomicBalanceKey>() + size_of::<u128>())
            + state.anchor_counts.len() * (size_of::<[u8; 32]>() + size_of::<u64>())
            + state.liquidity_vault_outpoints.len() * (size_of::<TransactionOutpoint>() + size_of::<[u8; 32]>())
            + liquidity_heap
    }
}

/// A DB + cache implementation of `DbAtomicStateStore` trait, with concurrency support.
#[derive(Clone)]
pub struct DbAtomicStateStore {
    db: Arc<DB>,
    access: CachedDbAccess<Hash, AtomicConsensusStateEntry, BlockHasher>,
}

impl DbAtomicStateStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self { db: Arc::clone(&db), access: CachedDbAccess::new(db, cache_policy, DatabaseStorePrefixes::AtomicState.into()) }
    }

    pub fn clone_with_new_cache(&self, cache_policy: CachePolicy) -> Self {
        Self::new(Arc::clone(&self.db), cache_policy)
    }

    pub fn insert_batch(&self, batch: &mut WriteBatch, hash: Hash, atomic_state: Arc<AtomicConsensusState>) -> Result<(), StoreError> {
        if self.access.has(hash)? {
            return Err(StoreError::HashAlreadyExists(hash));
        }
        self.access.write(BatchDbWriter::new(batch), hash, AtomicConsensusStateEntry(atomic_state))?;
        Ok(())
    }

    pub fn delete_batch(&self, batch: &mut WriteBatch, hash: Hash) -> Result<(), StoreError> {
        self.access.delete(BatchDbWriter::new(batch), hash)
    }
}

impl AtomicStateStoreReader for DbAtomicStateStore {
    fn get(&self, hash: Hash) -> Result<Arc<AtomicConsensusState>, StoreError> {
        Ok(self.access.read(hash)?.0)
    }
}

impl AtomicStateStore for DbAtomicStateStore {
    fn insert(&self, hash: Hash, atomic_state: Arc<AtomicConsensusState>) -> Result<(), StoreError> {
        if self.access.has(hash)? {
            return Err(StoreError::HashAlreadyExists(hash));
        }
        self.access.write(DirectDbWriter::new(&self.db), hash, AtomicConsensusStateEntry(atomic_state))?;
        Ok(())
    }

    fn delete(&self, hash: Hash) -> Result<(), StoreError> {
        self.access.delete(DirectDbWriter::new(&self.db), hash)
    }
}
