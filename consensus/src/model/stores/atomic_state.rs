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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomicAssetState {
    pub mint_authority_owner_id: [u8; 32],
    pub supply_mode: AtomicSupplyMode,
    pub max_supply: u128,
    pub total_supply: u128,
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
        size_of::<Self>()
            + state.next_nonces.len() * (size_of::<[u8; 32]>() + size_of::<u64>())
            + state.assets.len() * (size_of::<[u8; 32]>() + size_of::<AtomicAssetState>())
            + state.balances.len() * (size_of::<AtomicBalanceKey>() + size_of::<u128>())
            + state.anchor_counts.len() * (size_of::<[u8; 32]>() + size_of::<u64>())
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
