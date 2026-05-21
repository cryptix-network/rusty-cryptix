use crate::{
    error::{AtomicTokenError, AtomicTokenResult},
    state::{AtomicTokenState, BalanceKey, BlockJournal, LiquidityHolderAddressState, NonceKey, ProcessedOp, TokenAsset, TokenEvent},
};
use blake2b_simd::Params as Blake2bParams;
use cryptix_consensus_core::{tx::TransactionOutpoint, Hash as BlockHash};
use rocksdb::{checkpoint::Checkpoint, Options, WriteBatch, DB};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Mutex,
};

pub const ATOMIC_DB_SCHEMA_VERSION: u16 = 2;
pub const ATOMIC_REVALIDATION_VERSION: u16 = 17;

const META_SCHEMA_VERSION: &[u8] = b"meta/atomic_schema_version";
const META_PROTOCOL_VERSION: &[u8] = b"meta/atomic_protocol_version";
const META_CHAIN_ID: &[u8] = b"meta/atomic_chain_id";
const META_GENESIS_HASH: &[u8] = b"meta/atomic_genesis_hash";
const META_CURRENT_ROOT: &[u8] = b"meta/atomic_current_root";
const META_CURRENT_HEIGHT: &[u8] = b"meta/atomic_current_height";
const META_CURRENT_BLOCK_HASH: &[u8] = b"meta/atomic_current_block_hash";
const META_CHAIN_ORDER_BASE: &[u8] = b"meta/atomic_chain_order_base";
const META_DEGRADED: &[u8] = b"meta/atomic_degraded";
const META_NEXT_EVENT_SEQUENCE: &[u8] = b"meta/atomic_next_event_sequence";
const META_REVALIDATION_VERSION: &[u8] = b"meta/atomic_revalidation_version";

const PREFIX_ASSET: &[u8] = b"asset/";
const PREFIX_BALANCE: &[u8] = b"balance/";
const PREFIX_NONCE: &[u8] = b"nonce/";
const PREFIX_ANCHOR_COUNT: &[u8] = b"anchor/";
const PREFIX_PROCESSED_OP: &[u8] = b"processed_op/";
const PREFIX_JOURNAL: &[u8] = b"journal/";
const PREFIX_STATE_HASH: &[u8] = b"root/";
const PREFIX_EVENT_SEQUENCE: &[u8] = b"event_seq/";
const PREFIX_CHAIN_ORDER: &[u8] = b"chain_order/";
const PREFIX_EVENT: &[u8] = b"event/";
const PREFIX_LEAF_HASH: &[u8] = b"leaf_hash/";
const PREFIX_ROOT_BUCKET: &[u8] = b"root_bucket/";
const PREFIX_OWNER_BALANCE: &[u8] = b"owner_balance/";
const PREFIX_ASSET_HOLDER: &[u8] = b"asset_holder/";
const PREFIX_LIQUIDITY_VAULT: &[u8] = b"liquidity_vault/";
const PREFIX_KNOWN_OWNER_ADDRESS: &[u8] = b"known_owner_address/";

const ATOMIC_ROOT_BUCKETS: usize = 4096;
const RAW_STATE_COPY_CHUNK_KEYS: usize = 4096;
const ROOT_LEAF_DOMAIN: &[u8] = b"CRYPTIX_ATOMIC_V2_LEAF";
const ROOT_BUCKET_DOMAIN: &[u8] = b"CRYPTIX_ATOMIC_V2_BUCKETED_ROOT";
const LOGICAL_ASSET: u8 = 0x01;
const LOGICAL_BALANCE: u8 = 0x02;
const LOGICAL_NONCE: u8 = 0x03;
const LOGICAL_ANCHOR_COUNT: u8 = 0x04;

const STATE_PREFIXES: &[&[u8]] = &[
    PREFIX_ASSET,
    PREFIX_BALANCE,
    PREFIX_NONCE,
    PREFIX_ANCHOR_COUNT,
    PREFIX_PROCESSED_OP,
    PREFIX_JOURNAL,
    PREFIX_STATE_HASH,
    PREFIX_EVENT_SEQUENCE,
    PREFIX_CHAIN_ORDER,
    PREFIX_EVENT,
    PREFIX_LEAF_HASH,
    PREFIX_ROOT_BUCKET,
    PREFIX_OWNER_BALANCE,
    PREFIX_ASSET_HOLDER,
    PREFIX_LIQUIDITY_VAULT,
    PREFIX_KNOWN_OWNER_ADDRESS,
];

const CURRENT_STATE_COPY_PREFIXES: &[&[u8]] = &[
    PREFIX_ASSET,
    PREFIX_BALANCE,
    PREFIX_NONCE,
    PREFIX_ANCHOR_COUNT,
    PREFIX_PROCESSED_OP,
    PREFIX_LEAF_HASH,
    PREFIX_ROOT_BUCKET,
    PREFIX_OWNER_BALANCE,
    PREFIX_ASSET_HOLDER,
    PREFIX_LIQUIDITY_VAULT,
    PREFIX_KNOWN_OWNER_ADDRESS,
];

pub struct AtomicStorageV2 {
    path: PathBuf,
    db: DB,
    protocol_version: u16,
    network_id: String,
    genesis_hash: BlockHash,
    root_buckets_cache: Mutex<Option<[[u8; 32]; ATOMIC_ROOT_BUCKETS]>>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct AtomicStorageSnapshotCounts {
    pub assets: u64,
    pub balances: u64,
    pub nonces: u64,
    pub anchor_counts: u64,
    pub processed_ops: u64,
    pub state_hashes: u64,
    pub event_sequences: u64,
    pub chain_order: u64,
    pub events: u64,
}

impl std::fmt::Debug for AtomicStorageV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AtomicStorageV2")
            .field("path", &self.path)
            .field("protocol_version", &self.protocol_version)
            .field("network_id", &self.network_id)
            .field("genesis_hash", &self.genesis_hash)
            .finish_non_exhaustive()
    }
}

impl AtomicStorageV2 {
    pub fn open(
        path: impl AsRef<Path>,
        protocol_version: u16,
        network_id: String,
        genesis_hash: BlockHash,
    ) -> AtomicTokenResult<Self> {
        let path = path.as_ref().to_path_buf();
        let _ = remove_archived_wal_dir(&path);
        let mut options = Options::default();
        options.create_if_missing(true);
        options.set_keep_log_file_num(8);
        options.set_max_total_wal_size(64 * 1024 * 1024);
        options.set_wal_ttl_seconds(0);
        options.set_wal_size_limit_mb(0);
        let db = DB::open(&options, &path)
            .map_err(|err| AtomicTokenError::Processing(format!("failed opening Atomic DB schema v2: {err}")))?;
        let store = Self { path, db, protocol_version, network_id, genesis_hash, root_buckets_cache: Mutex::new(None) };
        store.initialize_or_validate_meta()?;
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn approximate_size_bytes(&self) -> Option<u64> {
        self.db
            .property_int_value("rocksdb.estimate-live-data-size")
            .ok()
            .flatten()
            .or_else(|| self.db.property_int_value("rocksdb.total-sst-files-size").ok().flatten())
    }

    pub fn checkpoint_to(&self, path: impl AsRef<Path>) -> AtomicTokenResult<()> {
        let path = path.as_ref();
        if path.exists() {
            std::fs::remove_dir_all(path).map_err(|err| {
                AtomicTokenError::Processing(format!("failed removing stale Atomic DB checkpoint `{}`: {err}", path.display()))
            })?;
        }
        let checkpoint = Checkpoint::new(&self.db)
            .map_err(|err| AtomicTokenError::Processing(format!("failed creating Atomic DB checkpoint handle: {err}")))?;
        checkpoint
            .create_checkpoint(path)
            .map_err(|err| AtomicTokenError::Processing(format!("failed creating Atomic DB checkpoint `{}`: {err}", path.display())))
    }

    pub fn current_root(&self) -> AtomicTokenResult<Option<[u8; 32]>> {
        self.get_typed(META_CURRENT_ROOT)
    }

    pub fn revalidation_version(&self) -> AtomicTokenResult<Option<u16>> {
        self.get_typed(META_REVALIDATION_VERSION)
    }

    pub fn get_asset(&self, asset_id: &[u8; 32]) -> AtomicTokenResult<Option<TokenAsset>> {
        self.get_typed(&asset_key(asset_id))
    }

    pub fn get_balance(&self, key: &BalanceKey) -> AtomicTokenResult<u128> {
        Ok(self.get_typed(&balance_key(key))?.unwrap_or(0))
    }

    pub fn get_nonce(&self, key: &NonceKey) -> AtomicTokenResult<u64> {
        Ok(self.get_typed(&nonce_key(key))?.unwrap_or(1))
    }

    pub fn get_anchor_count(&self, owner_id: &[u8; 32]) -> AtomicTokenResult<u64> {
        Ok(self.get_typed(&anchor_count_key(owner_id))?.unwrap_or(0))
    }

    pub fn get_processed_op(&self, txid: &BlockHash) -> AtomicTokenResult<Option<ProcessedOp>> {
        self.get_typed(&processed_op_key(txid))
    }

    pub fn get_liquidity_asset_by_vault_outpoint(&self, outpoint: &TransactionOutpoint) -> AtomicTokenResult<Option<[u8; 32]>> {
        self.get_typed(&liquidity_vault_key(outpoint))
    }

    pub fn get_known_owner_address(&self, owner_id: &[u8; 32]) -> AtomicTokenResult<Option<LiquidityHolderAddressState>> {
        self.get_typed(&known_owner_address_key(owner_id))
    }

    pub fn balances_by_owner(&self, owner_id: &[u8; 32]) -> AtomicTokenResult<Vec<([u8; 32], u128)>> {
        let mut entries = Vec::new();
        let prefix = owner_balance_prefix(owner_id);
        self.read_prefix(&prefix, |suffix, value| {
            let asset_id = decode_fixed_32(suffix, "owner balance asset id")?;
            let amount: u128 = decode_value(value, "owner balance")?;
            if amount > 0 {
                entries.push((asset_id, amount));
            }
            Ok(())
        })?;
        Ok(entries)
    }

    pub fn holders_by_asset(&self, asset_id: &[u8; 32]) -> AtomicTokenResult<Vec<([u8; 32], u128)>> {
        let mut entries = Vec::new();
        let prefix = asset_holder_prefix(asset_id);
        self.read_prefix(&prefix, |suffix, value| {
            let owner_id = decode_fixed_32(suffix, "asset holder owner id")?;
            let amount: u128 = decode_value(value, "asset holder")?;
            if amount > 0 {
                entries.push((owner_id, amount));
            }
            Ok(())
        })?;
        Ok(entries)
    }

    pub fn assets_page(&self, offset: usize, limit: usize, query: &str) -> AtomicTokenResult<(Vec<TokenAsset>, u64)> {
        self.assets_page_excluding(offset, limit, query, &HashSet::new())
    }

    pub fn assets_page_excluding(
        &self,
        offset: usize,
        limit: usize,
        query: &str,
        excluded_asset_ids: &HashSet<[u8; 32]>,
    ) -> AtomicTokenResult<(Vec<TokenAsset>, u64)> {
        let query = query.trim().to_ascii_lowercase();
        let mut matched = 0u64;
        let mut entries = Vec::with_capacity(limit.min(1024));
        self.read_prefix(PREFIX_ASSET, |suffix, value| {
            let asset_id = decode_fixed_32(suffix, "asset id")?;
            if excluded_asset_ids.contains(&asset_id) {
                return Ok(());
            }
            let asset: TokenAsset = decode_value(value, "asset")?;
            if asset.asset_id != asset_id {
                return Err(AtomicTokenError::Processing("Atomic DB asset key/id mismatch".to_string()));
            }
            if !asset_matches_query(&asset, &query) {
                return Ok(());
            }
            if matched >= offset as u64 && entries.len() < limit {
                entries.push(asset);
            }
            matched = matched.saturating_add(1);
            Ok(())
        })?;
        Ok((entries, matched))
    }

    pub fn visit_assets_excluding<F>(
        &self,
        query: &str,
        excluded_asset_ids: &HashSet<[u8; 32]>,
        mut visitor: F,
    ) -> AtomicTokenResult<()>
    where
        F: FnMut(TokenAsset) -> AtomicTokenResult<()>,
    {
        let query = query.trim().to_ascii_lowercase();
        self.read_prefix(PREFIX_ASSET, |suffix, value| {
            let asset_id = decode_fixed_32(suffix, "asset id")?;
            if excluded_asset_ids.contains(&asset_id) {
                return Ok(());
            }
            let asset: TokenAsset = decode_value(value, "asset")?;
            if asset.asset_id != asset_id {
                return Err(AtomicTokenError::Processing("Atomic DB asset key/id mismatch".to_string()));
            }
            if asset_matches_query(&asset, &query) {
                visitor(asset)?;
            }
            Ok(())
        })
    }

    pub fn load_runtime_state(&self) -> AtomicTokenResult<Option<AtomicTokenState>> {
        if self.get_raw(META_CURRENT_ROOT)?.is_none() {
            return Ok(None);
        }

        let mut state = AtomicTokenState::new(self.protocol_version, self.network_id.clone());
        state.degraded = self.get_typed(META_DEGRADED)?.unwrap_or(false);
        state.live_correct = false;
        state.next_event_sequence = self.get_typed(META_NEXT_EVENT_SEQUENCE)?.unwrap_or(0);
        self.load_runtime_history(&mut state)?;
        state.rebuild_event_id_index();
        Ok(Some(state))
    }

    pub fn load_state(&self) -> AtomicTokenResult<Option<AtomicTokenState>> {
        if self.get_raw(META_CURRENT_ROOT)?.is_none() {
            return Ok(None);
        }

        let mut state = AtomicTokenState::new(self.protocol_version, self.network_id.clone());
        state.degraded = self.get_typed(META_DEGRADED)?.unwrap_or(false);
        state.live_correct = false;
        state.next_event_sequence = self.get_typed(META_NEXT_EVENT_SEQUENCE)?.unwrap_or(0);

        self.read_prefix(PREFIX_ASSET, |suffix, value| {
            let asset_id = decode_fixed_32(suffix, "asset id")?;
            let asset: TokenAsset = decode_value(value, "asset")?;
            state.assets.insert(asset_id, asset);
            Ok(())
        })?;
        self.read_prefix(PREFIX_BALANCE, |suffix, value| {
            let key = decode_balance_key(suffix)?;
            let amount: u128 = decode_value(value, "balance")?;
            if amount > 0 {
                state.balances.insert(key, amount);
            }
            Ok(())
        })?;
        self.read_prefix(PREFIX_NONCE, |suffix, value| {
            let key = decode_nonce_key(suffix)?;
            let nonce: u64 = decode_value(value, "nonce")?;
            state.nonces.insert(key, nonce);
            Ok(())
        })?;
        self.read_prefix(PREFIX_ANCHOR_COUNT, |suffix, value| {
            let owner_id = decode_fixed_32(suffix, "anchor owner id")?;
            let count: u64 = decode_value(value, "anchor count")?;
            if count > 0 {
                state.anchor_counts.insert(owner_id, count);
            }
            Ok(())
        })?;
        self.read_prefix(PREFIX_PROCESSED_OP, |suffix, value| {
            let txid = decode_block_hash(suffix, "processed op txid")?;
            let op: ProcessedOp = decode_value(value, "processed op")?;
            state.processed_ops.insert(txid, op);
            Ok(())
        })?;
        self.load_runtime_history(&mut state)?;

        state.rebuild_event_id_index();
        state.rebuild_runtime_caches();
        Ok(Some(state))
    }

    pub fn snapshot_counts(&self) -> AtomicTokenResult<AtomicStorageSnapshotCounts> {
        Ok(AtomicStorageSnapshotCounts {
            assets: self.prefix_count(PREFIX_ASSET)?,
            balances: self.prefix_count(PREFIX_BALANCE)?,
            nonces: self.prefix_count(PREFIX_NONCE)?,
            anchor_counts: self.prefix_count(PREFIX_ANCHOR_COUNT)?,
            processed_ops: self.prefix_count(PREFIX_PROCESSED_OP)?,
            state_hashes: self.prefix_count(PREFIX_STATE_HASH)?,
            event_sequences: self.prefix_count(PREFIX_EVENT_SEQUENCE)?,
            chain_order: self.prefix_count(PREFIX_CHAIN_ORDER)?,
            events: self.prefix_count(PREFIX_EVENT)?,
        })
    }

    pub fn visit_all_assets<F>(&self, mut visitor: F) -> AtomicTokenResult<()>
    where
        F: FnMut([u8; 32], TokenAsset) -> AtomicTokenResult<()>,
    {
        self.read_prefix(PREFIX_ASSET, |suffix, value| {
            let asset_id = decode_fixed_32(suffix, "asset id")?;
            let asset: TokenAsset = decode_value(value, "asset")?;
            visitor(asset_id, asset)
        })
    }

    pub fn visit_all_balances<F>(&self, mut visitor: F) -> AtomicTokenResult<()>
    where
        F: FnMut(BalanceKey, u128) -> AtomicTokenResult<()>,
    {
        self.read_prefix(PREFIX_BALANCE, |suffix, value| {
            let key = decode_balance_key(suffix)?;
            let amount: u128 = decode_value(value, "balance")?;
            visitor(key, amount)
        })
    }

    pub fn visit_all_nonces<F>(&self, mut visitor: F) -> AtomicTokenResult<()>
    where
        F: FnMut(NonceKey, u64) -> AtomicTokenResult<()>,
    {
        self.read_prefix(PREFIX_NONCE, |suffix, value| {
            let key = decode_nonce_key(suffix)?;
            let nonce: u64 = decode_value(value, "nonce")?;
            visitor(key, nonce)
        })
    }

    pub fn visit_all_anchor_counts<F>(&self, mut visitor: F) -> AtomicTokenResult<()>
    where
        F: FnMut([u8; 32], u64) -> AtomicTokenResult<()>,
    {
        self.read_prefix(PREFIX_ANCHOR_COUNT, |suffix, value| {
            let owner_id = decode_fixed_32(suffix, "anchor owner id")?;
            let count: u64 = decode_value(value, "anchor count")?;
            visitor(owner_id, count)
        })
    }

    pub fn visit_all_processed_ops<F>(&self, mut visitor: F) -> AtomicTokenResult<()>
    where
        F: FnMut(BlockHash, ProcessedOp) -> AtomicTokenResult<()>,
    {
        self.read_prefix(PREFIX_PROCESSED_OP, |suffix, value| {
            let txid = decode_block_hash(suffix, "processed op txid")?;
            let op: ProcessedOp = decode_value(value, "processed op")?;
            visitor(txid, op)
        })
    }

    pub fn visit_all_state_hashes<F>(&self, mut visitor: F) -> AtomicTokenResult<()>
    where
        F: FnMut(BlockHash, [u8; 32]) -> AtomicTokenResult<()>,
    {
        self.read_prefix(PREFIX_STATE_HASH, |suffix, value| {
            let block_hash = decode_block_hash(suffix, "state hash block hash")?;
            let state_hash: [u8; 32] = decode_value(value, "state hash")?;
            visitor(block_hash, state_hash)
        })
    }

    pub fn visit_all_event_sequences<F>(&self, mut visitor: F) -> AtomicTokenResult<()>
    where
        F: FnMut(BlockHash, u64) -> AtomicTokenResult<()>,
    {
        self.read_prefix(PREFIX_EVENT_SEQUENCE, |suffix, value| {
            let block_hash = decode_block_hash(suffix, "event sequence block hash")?;
            let sequence: u64 = decode_value(value, "event sequence")?;
            visitor(block_hash, sequence)
        })
    }

    pub fn visit_all_chain_order<F>(&self, mut visitor: F) -> AtomicTokenResult<()>
    where
        F: FnMut(u64, BlockHash) -> AtomicTokenResult<()>,
    {
        let base = self.chain_order_base()?;
        self.read_prefix(PREFIX_CHAIN_ORDER, |suffix, value| {
            let index = decode_u64_suffix(suffix, "chain order index")?;
            let relative_index = index.checked_sub(base).ok_or_else(|| {
                AtomicTokenError::Processing(format!("Atomic DB chain order index `{index}` is below persisted base `{base}`"))
            })?;
            let block_hash: BlockHash = decode_value(value, "chain order block hash")?;
            visitor(relative_index, block_hash)
        })
    }

    pub fn visit_all_events<F>(&self, mut visitor: F) -> AtomicTokenResult<()>
    where
        F: FnMut(TokenEvent) -> AtomicTokenResult<()>,
    {
        self.read_prefix(PREFIX_EVENT, |suffix, value| {
            let _sequence = decode_event_key_suffix(suffix)?;
            let event: TokenEvent = decode_value(value, "event")?;
            visitor(event)
        })
    }

    fn load_runtime_history(&self, state: &mut AtomicTokenState) -> AtomicTokenResult<()> {
        self.read_prefix(PREFIX_JOURNAL, |suffix, value| {
            let block_hash = decode_block_hash(suffix, "journal block hash")?;
            let journal: BlockJournal = decode_value(value, "block journal")?;
            state.block_journals.insert(block_hash, journal);
            Ok(())
        })?;
        self.read_prefix(PREFIX_STATE_HASH, |suffix, value| {
            let block_hash = decode_block_hash(suffix, "state hash block hash")?;
            let state_hash: [u8; 32] = decode_value(value, "state hash")?;
            state.state_hash_by_block.insert(block_hash, state_hash);
            Ok(())
        })?;
        self.read_prefix(PREFIX_EVENT_SEQUENCE, |suffix, value| {
            let block_hash = decode_block_hash(suffix, "event sequence block hash")?;
            let sequence: u64 = decode_value(value, "event sequence")?;
            state.event_sequence_by_block.insert(block_hash, sequence);
            Ok(())
        })?;
        self.read_prefix(PREFIX_CHAIN_ORDER, |suffix, value| {
            let _index = decode_u64_suffix(suffix, "chain order index")?;
            let block_hash: BlockHash = decode_value(value, "chain order block hash")?;
            state.applied_chain_order.push(block_hash);
            Ok(())
        })?;
        self.read_prefix(PREFIX_EVENT, |suffix, value| {
            let _sequence = decode_event_key_suffix(suffix)?;
            let event: TokenEvent = decode_value(value, "event")?;
            state.events.push(event);
            Ok(())
        })
    }

    pub fn persist_state(&self, state: &AtomicTokenState) -> AtomicTokenResult<()> {
        let mut batch = WriteBatch::default();
        for prefix in STATE_PREFIXES {
            for key in self.keys_with_prefix(prefix)? {
                batch.delete(key);
            }
        }

        batch.put(META_SCHEMA_VERSION, encode_value(&ATOMIC_DB_SCHEMA_VERSION, "schema version")?);
        batch.put(META_PROTOCOL_VERSION, encode_value(&self.protocol_version, "protocol version")?);
        batch.put(META_CHAIN_ID, encode_value(&self.network_id, "chain id")?);
        batch.put(META_GENESIS_HASH, encode_value(&self.genesis_hash.as_bytes(), "genesis hash")?);
        let mut root_accumulator = RootAccumulator::default();
        batch.put(META_CURRENT_ROOT, encode_value(&[0u8; 32], "current root")?);
        batch.put(META_CURRENT_HEIGHT, encode_value(&(state.applied_chain_order.len() as u64), "current height")?);
        if let Some(current_block_hash) = state.applied_chain_order.last() {
            batch.put(META_CURRENT_BLOCK_HASH, encode_value(current_block_hash, "current block hash")?);
        } else {
            batch.delete(META_CURRENT_BLOCK_HASH);
        }
        batch.put(META_DEGRADED, encode_value(&state.degraded, "degraded flag")?);
        batch.put(META_NEXT_EVENT_SEQUENCE, encode_value(&state.next_event_sequence, "next event sequence")?);
        batch.put(META_REVALIDATION_VERSION, encode_value(&ATOMIC_REVALIDATION_VERSION, "revalidation version")?);

        for (asset_id, asset) in state.assets.iter() {
            let value = encode_value(asset, "asset")?;
            batch.put(asset_key(asset_id), &value);
            write_asset_secondary_indexes(&mut batch, asset)?;
            root_accumulator.set(logical_asset_key(asset_id), Some(root_value_for_asset(asset)));
        }
        for (key, amount) in state.balances.iter() {
            if *amount > 0 {
                let value = encode_value(amount, "balance")?;
                batch.put(balance_key(key), &value);
                write_balance_secondary_indexes(&mut batch, key, *amount)?;
                root_accumulator.set(logical_balance_key(key), Some(root_value_for_u128(*amount)));
            }
        }
        for (key, nonce) in state.nonces.iter() {
            if *nonce != 1 {
                let value = encode_value(nonce, "nonce")?;
                batch.put(nonce_key(key), &value);
                root_accumulator.set(logical_nonce_key(key), Some(root_value_for_u64(*nonce)));
            }
        }
        for (owner_id, count) in state.anchor_counts.iter() {
            if *count > 0 {
                let value = encode_value(count, "anchor count")?;
                batch.put(anchor_count_key(owner_id), &value);
                root_accumulator.set(logical_anchor_count_key(owner_id), Some(root_value_for_u64(*count)));
            }
        }
        for (txid, op) in state.processed_ops.iter() {
            let value = encode_value(op, "processed op")?;
            batch.put(processed_op_key(txid), &value);
        }
        for (block_hash, journal) in state.block_journals.iter() {
            batch.put(journal_key(block_hash), encode_value(journal, "block journal")?);
        }
        for (block_hash, state_hash) in state.state_hash_by_block.iter() {
            batch.put(state_hash_key(block_hash), encode_value(state_hash, "state hash")?);
        }
        for (block_hash, sequence) in state.event_sequence_by_block.iter() {
            batch.put(event_sequence_key(block_hash), encode_value(sequence, "event sequence")?);
        }
        for (index, block_hash) in state.applied_chain_order.iter().enumerate() {
            batch.put(chain_order_key(index as u64), encode_value(block_hash, "chain order block hash")?);
        }
        for event in state.events.iter() {
            batch.put(event_key(event), encode_value(event, "event")?);
        }

        let root = root_accumulator.write_to_batch(&mut batch)?;
        batch.put(META_CURRENT_ROOT, encode_value(&root, "current root")?);
        batch.put(META_CHAIN_ORDER_BASE, encode_value(&0u64, "chain order base")?);

        self.db
            .write(batch)
            .map_err(|err| AtomicTokenError::Processing(format!("failed committing Atomic DB schema v2 batch: {err}")))?;
        self.clear_root_buckets_cache()?;
        Ok(())
    }

    pub fn apply_current_state_delta(
        &self,
        asset_changes: impl IntoIterator<Item = ([u8; 32], Option<TokenAsset>)>,
        balance_changes: impl IntoIterator<Item = (BalanceKey, Option<u128>)>,
        nonce_changes: impl IntoIterator<Item = (NonceKey, Option<u64>)>,
        anchor_count_changes: impl IntoIterator<Item = ([u8; 32], Option<u64>)>,
        processed_op_changes: impl IntoIterator<Item = (BlockHash, Option<ProcessedOp>)>,
    ) -> AtomicTokenResult<[u8; 32]> {
        let mut batch = WriteBatch::default();
        let mut root_changes = Vec::new();
        self.write_state_changes_to_batch(
            &mut batch,
            &mut root_changes,
            asset_changes,
            balance_changes,
            nonce_changes,
            anchor_count_changes,
            processed_op_changes,
        )?;

        let root = self.apply_root_changes_to_batch(&mut batch, root_changes)?;
        batch.put(META_CURRENT_ROOT, encode_value(&root, "current root")?);
        self.db
            .write(batch)
            .map_err(|err| AtomicTokenError::Processing(format!("failed committing Atomic DB schema v2 delta: {err}")))?;
        Ok(root)
    }

    pub fn replace_current_state_from(&self, source: &AtomicStorageV2, state: &AtomicTokenState) -> AtomicTokenResult<[u8; 32]> {
        let root = source
            .current_root()?
            .ok_or_else(|| AtomicTokenError::Processing("Atomic DB copy failed: source V2 store has no current root".to_string()))?;

        let mut batch = WriteBatch::default();
        let mut pending = 0usize;
        for prefix in CURRENT_STATE_COPY_PREFIXES {
            for key in self.keys_with_prefix(prefix)? {
                batch.delete(key);
                pending = pending.saturating_add(1);
                if pending >= RAW_STATE_COPY_CHUNK_KEYS {
                    self.db
                        .write(batch)
                        .map_err(|err| AtomicTokenError::Processing(format!("failed clearing Atomic DB current-state keys: {err}")))?;
                    batch = WriteBatch::default();
                    pending = 0;
                }
            }
        }
        if pending > 0 {
            self.db
                .write(batch)
                .map_err(|err| AtomicTokenError::Processing(format!("failed clearing Atomic DB current-state keys: {err}")))?;
        }

        let mut batch = WriteBatch::default();
        let mut pending = 0usize;
        for prefix in CURRENT_STATE_COPY_PREFIXES {
            source.read_prefix(prefix, |suffix, value| {
                batch.put(prefixed_key(prefix, suffix), value);
                pending = pending.saturating_add(1);
                if pending >= RAW_STATE_COPY_CHUNK_KEYS {
                    let to_write = std::mem::take(&mut batch);
                    self.db
                        .write(to_write)
                        .map_err(|err| AtomicTokenError::Processing(format!("failed copying Atomic DB current-state keys: {err}")))?;
                    pending = 0;
                }
                Ok(())
            })?;
        }
        self.write_current_meta_to_batch(
            &mut batch,
            state.applied_chain_order.last().copied(),
            state.applied_chain_order.len() as u64,
            root,
            state.degraded,
            state.next_event_sequence,
        )?;
        self.db
            .write(batch)
            .map_err(|err| AtomicTokenError::Processing(format!("failed copying Atomic DB current-state keys: {err}")))?;
        self.clear_root_buckets_cache()?;

        Ok(root)
    }

    pub fn commit_applied_block_delta(
        &self,
        asset_changes: Vec<([u8; 32], Option<TokenAsset>)>,
        balance_changes: Vec<(BalanceKey, Option<u128>)>,
        nonce_changes: Vec<(NonceKey, Option<u64>)>,
        anchor_count_changes: Vec<([u8; 32], Option<u64>)>,
        processed_op_changes: Vec<(BlockHash, Option<ProcessedOp>)>,
        block_hash: BlockHash,
        journal: &BlockJournal,
        chain_index: u64,
        event_sequence: u64,
        new_events: &[TokenEvent],
        degraded: bool,
        next_event_sequence: u64,
    ) -> AtomicTokenResult<[u8; 32]> {
        let chain_order_index = self.chain_order_storage_index(chain_index)?;
        let mut batch = WriteBatch::default();
        let mut root_changes = Vec::new();
        self.write_state_changes_to_batch(
            &mut batch,
            &mut root_changes,
            asset_changes,
            balance_changes,
            nonce_changes,
            anchor_count_changes,
            processed_op_changes,
        )?;
        let root = self.apply_root_changes_to_batch(&mut batch, root_changes)?;

        batch.put(journal_key(&block_hash), encode_value(journal, "block journal")?);
        batch.put(state_hash_key(&block_hash), encode_value(&root, "state hash")?);
        batch.put(event_sequence_key(&block_hash), encode_value(&event_sequence, "event sequence")?);
        batch.put(chain_order_key(chain_order_index), encode_value(&block_hash, "chain order block hash")?);
        for event in new_events {
            batch.put(event_key(event), encode_value(event, "event")?);
        }
        self.write_current_meta_to_batch(
            &mut batch,
            Some(block_hash),
            chain_index.saturating_add(1),
            root,
            degraded,
            next_event_sequence,
        )?;

        self.db
            .write(batch)
            .map_err(|err| AtomicTokenError::Processing(format!("failed committing Atomic DB schema v2 applied block: {err}")))?;
        Ok(root)
    }

    pub fn commit_rollback_delta(
        &self,
        asset_changes: Vec<([u8; 32], Option<TokenAsset>)>,
        balance_changes: Vec<(BalanceKey, Option<u128>)>,
        nonce_changes: Vec<(NonceKey, Option<u64>)>,
        anchor_count_changes: Vec<([u8; 32], Option<u64>)>,
        processed_op_changes: Vec<(BlockHash, Option<ProcessedOp>)>,
        removed_block_hash: BlockHash,
        current_block_hash: Option<BlockHash>,
        chain_len: u64,
        new_events: &[TokenEvent],
        degraded: bool,
        next_event_sequence: u64,
    ) -> AtomicTokenResult<[u8; 32]> {
        let chain_order_index = self.chain_order_storage_index(chain_len)?;
        let mut batch = WriteBatch::default();
        let mut root_changes = Vec::new();
        self.write_state_changes_to_batch(
            &mut batch,
            &mut root_changes,
            asset_changes,
            balance_changes,
            nonce_changes,
            anchor_count_changes,
            processed_op_changes,
        )?;
        let root = self.apply_root_changes_to_batch(&mut batch, root_changes)?;

        batch.delete(journal_key(&removed_block_hash));
        batch.delete(state_hash_key(&removed_block_hash));
        batch.delete(event_sequence_key(&removed_block_hash));
        batch.delete(chain_order_key(chain_order_index));
        for event in new_events {
            batch.put(event_key(event), encode_value(event, "event")?);
        }
        self.write_current_meta_to_batch(&mut batch, current_block_hash, chain_len, root, degraded, next_event_sequence)?;

        self.db
            .write(batch)
            .map_err(|err| AtomicTokenError::Processing(format!("failed committing Atomic DB schema v2 rollback: {err}")))?;
        Ok(root)
    }

    pub fn persist_runtime_flags(
        &self,
        current_block_hash: Option<BlockHash>,
        chain_len: u64,
        degraded: bool,
        next_event_sequence: u64,
    ) -> AtomicTokenResult<()> {
        let root = self.current_root()?.unwrap_or([0u8; 32]);
        let mut batch = WriteBatch::default();
        self.write_current_meta_to_batch(&mut batch, current_block_hash, chain_len, root, degraded, next_event_sequence)?;
        self.db
            .write(batch)
            .map_err(|err| AtomicTokenError::Processing(format!("failed committing Atomic DB schema v2 runtime flags: {err}")))?;
        Ok(())
    }

    pub fn rebuild_current_root_from_state_data(
        &self,
        current_block_hash: Option<BlockHash>,
        chain_len: u64,
        degraded: bool,
        next_event_sequence: u64,
    ) -> AtomicTokenResult<[u8; 32]> {
        let mut root_accumulator = RootAccumulator::default();

        self.visit_all_assets(|asset_id, asset| {
            if asset.asset_id != asset_id {
                return Err(AtomicTokenError::Processing("Atomic DB asset key/id mismatch while rebuilding root".to_string()));
            }
            root_accumulator.set(logical_asset_key(&asset_id), Some(root_value_for_asset(&asset)));
            Ok(())
        })?;
        self.visit_all_balances(|key, amount| {
            if amount > 0 {
                root_accumulator.set(logical_balance_key(&key), Some(root_value_for_u128(amount)));
            }
            Ok(())
        })?;
        self.visit_all_nonces(|key, nonce| {
            if nonce != 1 {
                root_accumulator.set(logical_nonce_key(&key), Some(root_value_for_u64(nonce)));
            }
            Ok(())
        })?;
        self.visit_all_anchor_counts(|owner_id, count| {
            if count > 0 {
                root_accumulator.set(logical_anchor_count_key(&owner_id), Some(root_value_for_u64(count)));
            }
            Ok(())
        })?;

        let mut batch = WriteBatch::default();
        for key in self.keys_with_prefix(PREFIX_LEAF_HASH)? {
            batch.delete(key);
        }
        for key in self.keys_with_prefix(PREFIX_ROOT_BUCKET)? {
            batch.delete(key);
        }
        let root = root_accumulator.write_to_batch(&mut batch)?;
        self.write_current_meta_to_batch(&mut batch, current_block_hash, chain_len, root, degraded, next_event_sequence)?;
        self.db
            .write(batch)
            .map_err(|err| AtomicTokenError::Processing(format!("failed rebuilding Atomic DB schema v2 current root: {err}")))?;
        self.clear_root_buckets_cache()?;
        Ok(root)
    }

    pub fn replace_state_hashes(&self, state_hashes: impl IntoIterator<Item = (BlockHash, [u8; 32])>) -> AtomicTokenResult<usize> {
        let mut batch = WriteBatch::default();
        let mut count = 0usize;
        for (block_hash, state_hash) in state_hashes {
            batch.put(state_hash_key(&block_hash), encode_value(&state_hash, "state hash")?);
            count = count.saturating_add(1);
        }
        if count == 0 {
            return Ok(0);
        }
        self.db
            .write(batch)
            .map_err(|err| AtomicTokenError::Processing(format!("failed refreshing Atomic DB schema v2 state hashes: {err}")))?;
        Ok(count)
    }

    pub fn prune_state_hashes_except(&self, retained_hashes: &HashSet<BlockHash>) -> AtomicTokenResult<usize> {
        let mut batch = WriteBatch::default();
        let mut count = 0usize;
        for key in self.keys_with_prefix(PREFIX_STATE_HASH)? {
            let block_hash = decode_block_hash(&key[PREFIX_STATE_HASH.len()..], "state hash block hash")?;
            if !retained_hashes.contains(&block_hash) {
                batch.delete(key);
                count = count.saturating_add(1);
            }
        }
        if count == 0 {
            return Ok(0);
        }
        self.db
            .write(batch)
            .map_err(|err| AtomicTokenError::Processing(format!("failed pruning stale Atomic DB schema v2 state hashes: {err}")))?;
        Ok(count)
    }

    pub fn persist_revalidation_version(&self, version: u16) -> AtomicTokenResult<()> {
        let mut batch = WriteBatch::default();
        batch.put(META_REVALIDATION_VERSION, encode_value(&version, "revalidation version")?);
        self.db.write(batch).map_err(|err| {
            AtomicTokenError::Processing(format!("failed committing Atomic DB schema v2 revalidation version: {err}"))
        })?;
        Ok(())
    }

    pub fn prune_history(
        &self,
        pruned_hashes: &[BlockHash],
        pruned_processed_op_txids: &[BlockHash],
        retained_chain_order: &[BlockHash],
        last_pruned_event_sequence: Option<u64>,
    ) -> AtomicTokenResult<()> {
        if pruned_hashes.is_empty() {
            return Ok(());
        }
        let chain_order_base = self.chain_order_base()?;
        let mut batch = WriteBatch::default();
        for (offset, block_hash) in pruned_hashes.iter().enumerate() {
            batch.delete(journal_key(block_hash));
            batch.delete(state_hash_key(block_hash));
            batch.delete(event_sequence_key(block_hash));
            let index = chain_order_base
                .checked_add(offset as u64)
                .ok_or_else(|| AtomicTokenError::Processing("Atomic DB chain order base overflow during prune".to_string()))?;
            batch.delete(chain_order_key(index));
        }
        if let Some(last_pruned_event_sequence) = last_pruned_event_sequence {
            for key in self.keys_with_prefix(PREFIX_EVENT)? {
                let sequence = decode_event_key_suffix(&key[PREFIX_EVENT.len()..])?;
                if sequence <= last_pruned_event_sequence {
                    batch.delete(key);
                }
            }
        }
        for txid in pruned_processed_op_txids {
            batch.delete(processed_op_key(txid));
        }
        let root = self.current_root()?.unwrap_or([0u8; 32]);
        let new_chain_order_base = chain_order_base
            .checked_add(pruned_hashes.len() as u64)
            .ok_or_else(|| AtomicTokenError::Processing("Atomic DB chain order base overflow after prune".to_string()))?;
        batch.put(META_CURRENT_ROOT, encode_value(&root, "current root")?);
        batch.put(META_CURRENT_HEIGHT, encode_value(&(retained_chain_order.len() as u64), "current height")?);
        batch.put(META_CHAIN_ORDER_BASE, encode_value(&new_chain_order_base, "chain order base")?);
        self.db
            .write(batch)
            .map_err(|err| AtomicTokenError::Processing(format!("failed pruning Atomic DB schema v2 history: {err}")))?;
        Ok(())
    }

    fn write_state_changes_to_batch(
        &self,
        batch: &mut WriteBatch,
        root_changes: &mut Vec<(Vec<u8>, Option<Vec<u8>>)>,
        asset_changes: impl IntoIterator<Item = ([u8; 32], Option<TokenAsset>)>,
        balance_changes: impl IntoIterator<Item = (BalanceKey, Option<u128>)>,
        nonce_changes: impl IntoIterator<Item = (NonceKey, Option<u64>)>,
        anchor_count_changes: impl IntoIterator<Item = ([u8; 32], Option<u64>)>,
        processed_op_changes: impl IntoIterator<Item = (BlockHash, Option<ProcessedOp>)>,
    ) -> AtomicTokenResult<()> {
        let asset_changes: Vec<_> = asset_changes.into_iter().collect();
        let mut old_assets = HashMap::new();
        let mut changed_asset_ids = HashSet::new();
        let mut affected_known_owner_ids = HashSet::new();
        for (asset_id, value) in asset_changes.iter() {
            changed_asset_ids.insert(*asset_id);
            if let Some(old_asset) = self.get_asset(asset_id)? {
                collect_known_owner_ids(&old_asset, &mut affected_known_owner_ids);
                old_assets.insert(*asset_id, old_asset);
            }
            if let Some(asset) = value {
                collect_known_owner_ids(asset, &mut affected_known_owner_ids);
            }
        }

        for (asset_id, value) in asset_changes.iter() {
            let logical_key = logical_asset_key(&asset_id);
            if let Some(old_asset) = old_assets.get(asset_id) {
                delete_asset_secondary_indexes(batch, &old_asset);
            }
            match value {
                Some(asset) => {
                    let encoded = encode_value(&asset, "asset")?;
                    batch.put(asset_key(asset_id), &encoded);
                    write_asset_secondary_indexes(batch, &asset)?;
                    root_changes.push((logical_key, Some(root_value_for_asset(asset))));
                }
                None => {
                    batch.delete(asset_key(asset_id));
                    root_changes.push((logical_key, None));
                }
            }
        }
        self.rewrite_known_owner_addresses_for_asset_changes(batch, &affected_known_owner_ids, &changed_asset_ids, &asset_changes)?;
        for (key, value) in balance_changes {
            let logical_key = logical_balance_key(&key);
            match value.filter(|amount| *amount > 0) {
                Some(amount) => {
                    let encoded = encode_value(&amount, "balance")?;
                    batch.put(balance_key(&key), &encoded);
                    write_balance_secondary_indexes(batch, &key, amount)?;
                    root_changes.push((logical_key, Some(root_value_for_u128(amount))));
                }
                None => {
                    batch.delete(balance_key(&key));
                    delete_balance_secondary_indexes(batch, &key);
                    root_changes.push((logical_key, None));
                }
            }
        }
        for (key, value) in nonce_changes {
            let logical_key = logical_nonce_key(&key);
            match value {
                Some(nonce) => {
                    let encoded = encode_value(&nonce, "nonce")?;
                    batch.put(nonce_key(&key), &encoded);
                    root_changes.push((logical_key, Some(root_value_for_u64(nonce))));
                }
                None => {
                    batch.delete(nonce_key(&key));
                    root_changes.push((logical_key, None));
                }
            }
        }
        for (owner_id, value) in anchor_count_changes {
            let logical_key = logical_anchor_count_key(&owner_id);
            match value.filter(|count| *count > 0) {
                Some(count) => {
                    let encoded = encode_value(&count, "anchor count")?;
                    batch.put(anchor_count_key(&owner_id), &encoded);
                    root_changes.push((logical_key, Some(root_value_for_u64(count))));
                }
                None => {
                    batch.delete(anchor_count_key(&owner_id));
                    root_changes.push((logical_key, None));
                }
            }
        }
        for (txid, value) in processed_op_changes {
            match value {
                Some(op) => {
                    let encoded = encode_value(&op, "processed op")?;
                    batch.put(processed_op_key(&txid), &encoded);
                }
                None => {
                    batch.delete(processed_op_key(&txid));
                }
            }
        }
        Ok(())
    }

    fn rewrite_known_owner_addresses_for_asset_changes(
        &self,
        batch: &mut WriteBatch,
        owner_ids: &HashSet<[u8; 32]>,
        changed_asset_ids: &HashSet<[u8; 32]>,
        asset_changes: &[([u8; 32], Option<TokenAsset>)],
    ) -> AtomicTokenResult<()> {
        if owner_ids.is_empty() {
            return Ok(());
        }

        let mut addresses = HashMap::new();
        for (_, asset) in asset_changes.iter() {
            if let Some(asset) = asset {
                record_known_owner_addresses_for_asset(asset, Some(owner_ids), &mut addresses);
            }
        }
        self.visit_all_assets(|asset_id, asset| {
            if changed_asset_ids.contains(&asset_id) {
                return Ok(());
            }
            record_known_owner_addresses_for_asset(&asset, Some(owner_ids), &mut addresses);
            Ok(())
        })?;

        for owner_id in owner_ids {
            match addresses.get(owner_id) {
                Some(address) => {
                    batch.put(known_owner_address_key(owner_id), encode_value(address, "known owner address")?);
                }
                None => {
                    batch.delete(known_owner_address_key(owner_id));
                }
            }
        }
        Ok(())
    }

    fn write_current_meta_to_batch(
        &self,
        batch: &mut WriteBatch,
        current_block_hash: Option<BlockHash>,
        chain_len: u64,
        root: [u8; 32],
        degraded: bool,
        next_event_sequence: u64,
    ) -> AtomicTokenResult<()> {
        batch.put(META_SCHEMA_VERSION, encode_value(&ATOMIC_DB_SCHEMA_VERSION, "schema version")?);
        batch.put(META_PROTOCOL_VERSION, encode_value(&self.protocol_version, "protocol version")?);
        batch.put(META_CHAIN_ID, encode_value(&self.network_id, "chain id")?);
        batch.put(META_GENESIS_HASH, encode_value(&self.genesis_hash.as_bytes(), "genesis hash")?);
        batch.put(META_CURRENT_ROOT, encode_value(&root, "current root")?);
        batch.put(META_CURRENT_HEIGHT, encode_value(&chain_len, "current height")?);
        if let Some(current_block_hash) = current_block_hash {
            batch.put(META_CURRENT_BLOCK_HASH, encode_value(&current_block_hash, "current block hash")?);
        } else {
            batch.delete(META_CURRENT_BLOCK_HASH);
        }
        batch.put(META_DEGRADED, encode_value(&degraded, "degraded flag")?);
        batch.put(META_NEXT_EVENT_SEQUENCE, encode_value(&next_event_sequence, "next event sequence")?);
        Ok(())
    }

    fn chain_order_base(&self) -> AtomicTokenResult<u64> {
        self.get_typed(META_CHAIN_ORDER_BASE).map(|value| value.unwrap_or(0))
    }

    fn chain_order_storage_index(&self, relative_index: u64) -> AtomicTokenResult<u64> {
        self.chain_order_base()?
            .checked_add(relative_index)
            .ok_or_else(|| AtomicTokenError::Processing("Atomic DB chain order storage index overflow".to_string()))
    }

    fn initialize_or_validate_meta(&self) -> AtomicTokenResult<()> {
        let Some(schema_version) = self.get_typed::<u16>(META_SCHEMA_VERSION)? else {
            let mut batch = WriteBatch::default();
            batch.put(META_SCHEMA_VERSION, encode_value(&ATOMIC_DB_SCHEMA_VERSION, "schema version")?);
            batch.put(META_PROTOCOL_VERSION, encode_value(&self.protocol_version, "protocol version")?);
            batch.put(META_CHAIN_ID, encode_value(&self.network_id, "chain id")?);
            batch.put(META_GENESIS_HASH, encode_value(&self.genesis_hash.as_bytes(), "genesis hash")?);
            self.db
                .write(batch)
                .map_err(|err| AtomicTokenError::Processing(format!("failed initializing Atomic DB schema v2 metadata: {err}")))?;
            return Ok(());
        };

        if schema_version != ATOMIC_DB_SCHEMA_VERSION {
            return Err(AtomicTokenError::Processing(format!(
                "Atomic DB schema mismatch: expected `{ATOMIC_DB_SCHEMA_VERSION}`, got `{schema_version}`"
            )));
        }
        let stored_protocol_version = self
            .get_typed::<u16>(META_PROTOCOL_VERSION)?
            .ok_or_else(|| AtomicTokenError::Processing("Atomic DB schema v2 is missing protocol version metadata".to_string()))?;
        if stored_protocol_version != self.protocol_version {
            return Err(AtomicTokenError::Processing(format!(
                "Atomic DB protocol mismatch: expected `{}`, got `{stored_protocol_version}`",
                self.protocol_version
            )));
        }
        let stored_network_id = self
            .get_typed::<String>(META_CHAIN_ID)?
            .ok_or_else(|| AtomicTokenError::Processing("Atomic DB schema v2 is missing chain id metadata".to_string()))?;
        if stored_network_id != self.network_id {
            return Err(AtomicTokenError::Processing(format!(
                "Atomic DB chain mismatch: expected `{}`, got `{stored_network_id}`",
                self.network_id
            )));
        }
        let stored_genesis_hash = self
            .get_typed::<[u8; 32]>(META_GENESIS_HASH)?
            .ok_or_else(|| AtomicTokenError::Processing("Atomic DB schema v2 is missing genesis hash metadata".to_string()))?;
        if stored_genesis_hash != self.genesis_hash.as_bytes() {
            return Err(AtomicTokenError::Processing(
                "Atomic DB genesis hash mismatch; reset the Atomic data directory for this network".to_string(),
            ));
        }
        Ok(())
    }

    fn get_raw(&self, key: &[u8]) -> AtomicTokenResult<Option<Vec<u8>>> {
        self.db.get(key).map_err(|err| AtomicTokenError::Processing(format!("failed reading Atomic DB schema v2: {err}")))
    }

    fn get_typed<T: DeserializeOwned>(&self, key: &[u8]) -> AtomicTokenResult<Option<T>> {
        self.get_raw(key)?.map(|value| decode_value(&value, "metadata")).transpose()
    }

    fn read_prefix<F>(&self, prefix: &[u8], mut visitor: F) -> AtomicTokenResult<()>
    where
        F: FnMut(&[u8], &[u8]) -> AtomicTokenResult<()>,
    {
        let iter = self.db.prefix_iterator(prefix);
        for item in iter {
            let (key, value) =
                item.map_err(|err| AtomicTokenError::Processing(format!("failed iterating Atomic DB schema v2: {err}")))?;
            if !key.starts_with(prefix) {
                break;
            }
            visitor(&key[prefix.len()..], &value)?;
        }
        Ok(())
    }

    fn prefix_count(&self, prefix: &[u8]) -> AtomicTokenResult<u64> {
        let mut count = 0u64;
        self.read_prefix(prefix, |_, _| {
            count = count.saturating_add(1);
            Ok(())
        })?;
        Ok(count)
    }

    fn keys_with_prefix(&self, prefix: &[u8]) -> AtomicTokenResult<Vec<Vec<u8>>> {
        let mut keys = Vec::new();
        self.read_prefix(prefix, |suffix, _| {
            let mut key = Vec::with_capacity(prefix.len() + suffix.len());
            key.extend_from_slice(prefix);
            key.extend_from_slice(suffix);
            keys.push(key);
            Ok(())
        })?;
        Ok(keys)
    }

    fn apply_root_changes_to_batch(
        &self,
        batch: &mut WriteBatch,
        changes: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    ) -> AtomicTokenResult<[u8; 32]> {
        let mut cache = self
            .root_buckets_cache
            .lock()
            .map_err(|_| AtomicTokenError::Processing("Atomic DB root bucket cache lock is poisoned".to_string()))?;
        if cache.is_none() {
            *cache = Some(self.load_root_buckets()?);
        }
        let buckets = cache.as_mut().expect("root bucket cache initialized");
        for (logical_key, value) in changes {
            let leaf_key = leaf_hash_key(&logical_key);
            let old_leaf = self.get_typed::<[u8; 32]>(&leaf_key)?.unwrap_or([0u8; 32]);
            let new_leaf = value.as_ref().map(|encoded| root_leaf_hash(&logical_key, encoded)).unwrap_or([0u8; 32]);
            if old_leaf == new_leaf {
                continue;
            }
            let bucket_index = root_bucket_index(&logical_key);
            xor_hash(&mut buckets[bucket_index], old_leaf);
            xor_hash(&mut buckets[bucket_index], new_leaf);
            if new_leaf == [0u8; 32] {
                batch.delete(leaf_key);
            } else {
                batch.put(leaf_key, encode_value(&new_leaf, "root leaf hash")?);
            }
            batch.put(root_bucket_key(bucket_index as u16), encode_value(&buckets[bucket_index], "root bucket")?);
        }
        Ok(root_from_buckets(&buckets))
    }

    fn clear_root_buckets_cache(&self) -> AtomicTokenResult<()> {
        let mut cache = self
            .root_buckets_cache
            .lock()
            .map_err(|_| AtomicTokenError::Processing("Atomic DB root bucket cache lock is poisoned".to_string()))?;
        *cache = None;
        Ok(())
    }

    fn load_root_buckets(&self) -> AtomicTokenResult<[[u8; 32]; ATOMIC_ROOT_BUCKETS]> {
        let mut buckets = [[0u8; 32]; ATOMIC_ROOT_BUCKETS];
        self.read_prefix(PREFIX_ROOT_BUCKET, |suffix, value| {
            let index = decode_u16_suffix(suffix, "root bucket index")? as usize;
            if index >= ATOMIC_ROOT_BUCKETS {
                return Err(AtomicTokenError::Processing(format!("Atomic DB root bucket index `{index}` is out of range")));
            }
            buckets[index] = decode_value(value, "root bucket")?;
            Ok(())
        })?;
        Ok(buckets)
    }
}

#[derive(Default)]
struct RootAccumulator {
    leaves: Vec<(Vec<u8>, Vec<u8>)>,
}

impl RootAccumulator {
    fn set(&mut self, logical_key: Vec<u8>, value: Option<Vec<u8>>) {
        if let Some(value) = value {
            self.leaves.push((logical_key, value));
        }
    }

    fn write_to_batch(self, batch: &mut WriteBatch) -> AtomicTokenResult<[u8; 32]> {
        let mut buckets = [[0u8; 32]; ATOMIC_ROOT_BUCKETS];
        for (logical_key, value) in self.leaves {
            let leaf_hash = root_leaf_hash(&logical_key, &value);
            let bucket_index = root_bucket_index(&logical_key);
            xor_hash(&mut buckets[bucket_index], leaf_hash);
            batch.put(leaf_hash_key(&logical_key), encode_value(&leaf_hash, "root leaf hash")?);
        }
        for (index, bucket) in buckets.iter().enumerate() {
            if *bucket != [0u8; 32] {
                batch.put(root_bucket_key(index as u16), encode_value(bucket, "root bucket")?);
            }
        }
        Ok(root_from_buckets(&buckets))
    }
}

fn encode_value<T: Serialize>(value: &T, label: &str) -> AtomicTokenResult<Vec<u8>> {
    bincode::serialize(value).map_err(|err| AtomicTokenError::Processing(format!("failed encoding Atomic DB {label}: {err}")))
}

fn decode_value<T: DeserializeOwned>(value: &[u8], label: &str) -> AtomicTokenResult<T> {
    bincode::deserialize(value).map_err(|err| AtomicTokenError::Processing(format!("failed decoding Atomic DB {label}: {err}")))
}

fn asset_matches_query(asset: &TokenAsset, query: &str) -> bool {
    if query.is_empty() {
        return true;
    }

    let symbol = String::from_utf8_lossy(&asset.symbol).to_ascii_lowercase();
    let name = String::from_utf8_lossy(&asset.name).to_ascii_lowercase();
    let asset_id = hex_lower(&asset.asset_id);
    symbol.contains(query) || name.contains(query) || asset_id.starts_with(query)
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

fn prefixed_key(prefix: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + suffix.len());
    key.extend_from_slice(prefix);
    key.extend_from_slice(suffix);
    key
}

fn asset_key(asset_id: &[u8; 32]) -> Vec<u8> {
    prefixed_key(PREFIX_ASSET, asset_id)
}

fn balance_key(key: &BalanceKey) -> Vec<u8> {
    let mut suffix = Vec::with_capacity(64);
    suffix.extend_from_slice(&key.asset_id);
    suffix.extend_from_slice(&key.owner_id);
    prefixed_key(PREFIX_BALANCE, &suffix)
}

fn nonce_key(key: &NonceKey) -> Vec<u8> {
    let mut suffix = Vec::with_capacity(65);
    suffix.extend_from_slice(&key.owner_id);
    suffix.push(key.scope_kind);
    suffix.extend_from_slice(&key.scope_id);
    prefixed_key(PREFIX_NONCE, &suffix)
}

fn anchor_count_key(owner_id: &[u8; 32]) -> Vec<u8> {
    prefixed_key(PREFIX_ANCHOR_COUNT, owner_id)
}

fn processed_op_key(txid: &BlockHash) -> Vec<u8> {
    prefixed_key(PREFIX_PROCESSED_OP, &txid.as_bytes())
}

fn journal_key(block_hash: &BlockHash) -> Vec<u8> {
    prefixed_key(PREFIX_JOURNAL, &block_hash.as_bytes())
}

fn state_hash_key(block_hash: &BlockHash) -> Vec<u8> {
    prefixed_key(PREFIX_STATE_HASH, &block_hash.as_bytes())
}

fn event_sequence_key(block_hash: &BlockHash) -> Vec<u8> {
    prefixed_key(PREFIX_EVENT_SEQUENCE, &block_hash.as_bytes())
}

fn chain_order_key(index: u64) -> Vec<u8> {
    prefixed_key(PREFIX_CHAIN_ORDER, &index.to_be_bytes())
}

fn event_key(event: &TokenEvent) -> Vec<u8> {
    let mut suffix = Vec::with_capacity(40);
    suffix.extend_from_slice(&event.sequence.to_be_bytes());
    suffix.extend_from_slice(&event.event_id);
    prefixed_key(PREFIX_EVENT, &suffix)
}

fn owner_balance_prefix(owner_id: &[u8; 32]) -> Vec<u8> {
    prefixed_key(PREFIX_OWNER_BALANCE, owner_id)
}

fn owner_balance_key(key: &BalanceKey) -> Vec<u8> {
    let mut suffix = Vec::with_capacity(64);
    suffix.extend_from_slice(&key.owner_id);
    suffix.extend_from_slice(&key.asset_id);
    prefixed_key(PREFIX_OWNER_BALANCE, &suffix)
}

fn asset_holder_prefix(asset_id: &[u8; 32]) -> Vec<u8> {
    prefixed_key(PREFIX_ASSET_HOLDER, asset_id)
}

fn asset_holder_key(key: &BalanceKey) -> Vec<u8> {
    let mut suffix = Vec::with_capacity(64);
    suffix.extend_from_slice(&key.asset_id);
    suffix.extend_from_slice(&key.owner_id);
    prefixed_key(PREFIX_ASSET_HOLDER, &suffix)
}

fn liquidity_vault_key(outpoint: &TransactionOutpoint) -> Vec<u8> {
    let mut suffix = Vec::with_capacity(36);
    suffix.extend_from_slice(&outpoint.transaction_id.as_bytes());
    suffix.extend_from_slice(&outpoint.index.to_be_bytes());
    prefixed_key(PREFIX_LIQUIDITY_VAULT, &suffix)
}

fn known_owner_address_key(owner_id: &[u8; 32]) -> Vec<u8> {
    prefixed_key(PREFIX_KNOWN_OWNER_ADDRESS, owner_id)
}

fn write_balance_secondary_indexes(batch: &mut WriteBatch, key: &BalanceKey, amount: u128) -> AtomicTokenResult<()> {
    batch.put(owner_balance_key(key), encode_value(&amount, "owner balance")?);
    batch.put(asset_holder_key(key), encode_value(&amount, "asset holder")?);
    Ok(())
}

fn delete_balance_secondary_indexes(batch: &mut WriteBatch, key: &BalanceKey) {
    batch.delete(owner_balance_key(key));
    batch.delete(asset_holder_key(key));
}

fn write_asset_secondary_indexes(batch: &mut WriteBatch, asset: &TokenAsset) -> AtomicTokenResult<()> {
    let Some(pool) = asset.liquidity.as_ref() else {
        return Ok(());
    };
    batch.put(liquidity_vault_key(&pool.vault_outpoint), encode_value(&asset.asset_id, "liquidity vault asset id")?);
    let mut addresses = HashMap::new();
    record_known_owner_addresses_for_asset(asset, None, &mut addresses);
    for (owner_id, address) in addresses {
        batch.put(known_owner_address_key(&owner_id), encode_value(&address, "known owner address")?);
    }
    Ok(())
}

fn delete_asset_secondary_indexes(batch: &mut WriteBatch, asset: &TokenAsset) {
    if let Some(pool) = asset.liquidity.as_ref() {
        batch.delete(liquidity_vault_key(&pool.vault_outpoint));
    }
}

fn collect_known_owner_ids(asset: &TokenAsset, out: &mut HashSet<[u8; 32]>) {
    let Some(pool) = asset.liquidity.as_ref() else {
        return;
    };
    for recipient in pool.fee_recipients.iter() {
        out.insert(recipient.owner_id);
    }
    for owner_id in pool.holder_addresses.keys() {
        out.insert(*owner_id);
    }
}

fn record_known_owner_addresses_for_asset(
    asset: &TokenAsset,
    owner_filter: Option<&HashSet<[u8; 32]>>,
    out: &mut HashMap<[u8; 32], LiquidityHolderAddressState>,
) {
    let Some(pool) = asset.liquidity.as_ref() else {
        return;
    };
    for recipient in pool.fee_recipients.iter() {
        if owner_filter.is_some_and(|owners| !owners.contains(&recipient.owner_id)) {
            continue;
        }
        out.entry(recipient.owner_id).or_insert_with(|| LiquidityHolderAddressState {
            address_version: recipient.address_version,
            address_payload: recipient.address_payload.clone(),
        });
    }
    for (owner_id, holder) in pool.holder_addresses.iter() {
        if owner_filter.is_some_and(|owners| !owners.contains(owner_id)) {
            continue;
        }
        out.entry(*owner_id).or_insert_with(|| holder.clone());
    }
}

fn leaf_hash_key(logical_key: &[u8]) -> Vec<u8> {
    prefixed_key(PREFIX_LEAF_HASH, logical_key)
}

fn root_bucket_key(index: u16) -> Vec<u8> {
    prefixed_key(PREFIX_ROOT_BUCKET, &index.to_be_bytes())
}

fn logical_asset_key(asset_id: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(33);
    key.push(LOGICAL_ASSET);
    key.extend_from_slice(asset_id);
    key
}

fn logical_balance_key(key: &BalanceKey) -> Vec<u8> {
    let mut logical = Vec::with_capacity(65);
    logical.push(LOGICAL_BALANCE);
    logical.extend_from_slice(&key.asset_id);
    logical.extend_from_slice(&key.owner_id);
    logical
}

fn logical_nonce_key(key: &NonceKey) -> Vec<u8> {
    let mut logical = Vec::with_capacity(66);
    logical.push(LOGICAL_NONCE);
    logical.extend_from_slice(&key.owner_id);
    logical.push(key.scope_kind);
    logical.extend_from_slice(&key.scope_id);
    logical
}

fn logical_anchor_count_key(owner_id: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(33);
    key.push(LOGICAL_ANCHOR_COUNT);
    key.extend_from_slice(owner_id);
    key
}

pub(crate) fn compute_state_root_from_parts(
    assets: &HashMap<[u8; 32], TokenAsset>,
    balances: &HashMap<BalanceKey, u128>,
    nonces: &HashMap<NonceKey, u64>,
    anchor_counts: &HashMap<[u8; 32], u64>,
) -> [u8; 32] {
    let mut buckets = [[0u8; 32]; ATOMIC_ROOT_BUCKETS];

    let mut asset_ids = assets.keys().copied().collect::<Vec<_>>();
    asset_ids.sort_unstable();
    for asset_id in asset_ids {
        if let Some(asset) = assets.get(&asset_id) {
            apply_root_leaf(&mut buckets, &logical_asset_key(&asset_id), &root_value_for_asset(asset));
        }
    }

    let mut balance_keys = balances.keys().copied().collect::<Vec<_>>();
    balance_keys.sort_unstable();
    for key in balance_keys {
        if let Some(amount) = balances.get(&key).copied().filter(|amount| *amount > 0) {
            apply_root_leaf(&mut buckets, &logical_balance_key(&key), &root_value_for_u128(amount));
        }
    }

    let mut nonce_keys = nonces.keys().copied().collect::<Vec<_>>();
    nonce_keys.sort_unstable();
    for key in nonce_keys {
        if let Some(nonce) = nonces.get(&key).copied().filter(|nonce| *nonce != 1) {
            apply_root_leaf(&mut buckets, &logical_nonce_key(&key), &root_value_for_u64(nonce));
        }
    }

    let mut anchor_count_owners = anchor_counts.keys().copied().collect::<Vec<_>>();
    anchor_count_owners.sort_unstable();
    for owner_id in anchor_count_owners {
        if let Some(count) = anchor_counts.get(&owner_id).copied().filter(|count| *count > 0) {
            apply_root_leaf(&mut buckets, &logical_anchor_count_key(&owner_id), &root_value_for_u64(count));
        }
    }

    root_from_buckets(&buckets)
}

pub(crate) fn debug_state_root_report_from_parts(
    assets: &HashMap<[u8; 32], TokenAsset>,
    balances: &HashMap<BalanceKey, u128>,
    nonces: &HashMap<NonceKey, u64>,
    anchor_counts: &HashMap<[u8; 32], u64>,
    max_entries: usize,
) -> String {
    let max_entries = max_entries.max(1);
    let mut lines = Vec::new();
    let root = compute_state_root_from_parts(assets, balances, nonces, anchor_counts);
    lines.push(format!(
        "token_root={} assets={} balances={} nonces={} anchor_counts={}",
        hex_lower(&root),
        assets.len(),
        balances.values().filter(|amount| **amount > 0).count(),
        nonces.values().filter(|nonce| **nonce != 1).count(),
        anchor_counts.values().filter(|count| **count > 0).count()
    ));

    let mut asset_ids = assets.keys().copied().collect::<Vec<_>>();
    asset_ids.sort_unstable();
    for (index, asset_id) in asset_ids.iter().copied().enumerate() {
        if index >= max_entries {
            lines.push(format!("asset_more={}", asset_ids.len() - index));
            break;
        }
        if let Some(asset) = assets.get(&asset_id) {
            let logical_key = logical_asset_key(&asset_id);
            let leaf = root_leaf_hash(&logical_key, &root_value_for_asset(asset));
            lines.push(format!(
                "asset[{index}] bucket={} leaf={} {}",
                root_bucket_index(&logical_key),
                hex_lower(&leaf),
                debug_asset_summary(asset)
            ));
        }
    }

    let mut balance_keys = balances.keys().copied().filter(|key| balances.get(key).copied().unwrap_or(0) > 0).collect::<Vec<_>>();
    balance_keys.sort_unstable();
    for (index, key) in balance_keys.iter().copied().enumerate() {
        if index >= max_entries {
            lines.push(format!("balance_more={}", balance_keys.len() - index));
            break;
        }
        let amount = balances.get(&key).copied().unwrap_or(0);
        let logical_key = logical_balance_key(&key);
        let leaf = root_leaf_hash(&logical_key, &root_value_for_u128(amount));
        lines.push(format!(
            "balance[{index}] bucket={} leaf={} asset={} owner={} amount={}",
            root_bucket_index(&logical_key),
            hex_lower(&leaf),
            hex_lower(&key.asset_id),
            hex_lower(&key.owner_id),
            amount
        ));
    }

    let mut nonce_keys = nonces.keys().copied().filter(|key| nonces.get(key).copied().unwrap_or(1) != 1).collect::<Vec<_>>();
    nonce_keys.sort_unstable();
    for (index, key) in nonce_keys.iter().copied().enumerate() {
        if index >= max_entries {
            lines.push(format!("nonce_more={}", nonce_keys.len() - index));
            break;
        }
        let nonce = nonces.get(&key).copied().unwrap_or(1);
        let logical_key = logical_nonce_key(&key);
        let leaf = root_leaf_hash(&logical_key, &root_value_for_u64(nonce));
        lines.push(format!(
            "nonce[{index}] bucket={} leaf={} owner={} scope_kind={} scope_id={} value={}",
            root_bucket_index(&logical_key),
            hex_lower(&leaf),
            hex_lower(&key.owner_id),
            key.scope_kind,
            hex_lower(&key.scope_id),
            nonce
        ));
    }

    let mut owners =
        anchor_counts.keys().copied().filter(|owner_id| anchor_counts.get(owner_id).copied().unwrap_or(0) > 0).collect::<Vec<_>>();
    owners.sort_unstable();
    for (index, owner_id) in owners.iter().copied().enumerate() {
        if index >= max_entries {
            lines.push(format!("anchor_more={}", owners.len() - index));
            break;
        }
        let count = anchor_counts.get(&owner_id).copied().unwrap_or(0);
        let logical_key = logical_anchor_count_key(&owner_id);
        let leaf = root_leaf_hash(&logical_key, &root_value_for_u64(count));
        lines.push(format!(
            "anchor[{index}] bucket={} leaf={} owner={} count={}",
            root_bucket_index(&logical_key),
            hex_lower(&leaf),
            hex_lower(&owner_id),
            count
        ));
    }

    lines.join("\n")
}

fn debug_asset_summary(asset: &TokenAsset) -> String {
    let mut out = format!(
        "asset={} class={:?} token_version={} creator={} mint_authority={} decimals={} supply_mode={:?} max_supply={} total_supply={} name_hex={} symbol_hex={} metadata_hex={} platform_hex={} created_block={} created_daa={} created_at={}",
        hex_lower(&asset.asset_id),
        asset.asset_class,
        asset.token_version,
        hex_lower(&asset.creator_owner_id),
        hex_lower(&asset.mint_authority_owner_id),
        asset.decimals,
        asset.supply_mode,
        asset.max_supply,
        asset.total_supply,
        hex_lower(&asset.name),
        hex_lower(&asset.symbol),
        hex_lower(&asset.metadata),
        hex_lower(&asset.platform_tag),
        asset.created_block_hash.map(|hash| hash.to_string()).unwrap_or_else(|| "<none>".to_string()),
        asset.created_daa_score.map(|value| value.to_string()).unwrap_or_else(|| "<none>".to_string()),
        asset.created_at.map(|value| value.to_string()).unwrap_or_else(|| "<none>".to_string())
    );
    let Some(pool) = asset.liquidity.as_ref() else {
        out.push_str(" liquidity=<none>");
        return out;
    };
    out.push_str(&format!(
        " liquidity={{pool_nonce={} curve_version={} curve_mode={} iv_cpay={} iv_token_bps={} real_cpay={} real_token={} virtual_cpay={} virtual_token={} unclaimed_fee_total={} fee_bps={} vault_outpoint={} vault_value={} unlock_target={} unlocked={} recipients={}",
        pool.pool_nonce,
        pool.curve_version,
        pool.curve_mode,
        pool.individual_virtual_cpay_reserves_sompi,
        pool.individual_virtual_token_multiplier_bps,
        pool.real_cpay_reserves_sompi,
        pool.real_token_reserves,
        pool.virtual_cpay_reserves_sompi,
        pool.virtual_token_reserves,
        pool.unclaimed_fee_total_sompi,
        pool.fee_bps,
        pool.vault_outpoint,
        pool.vault_value_sompi,
        pool.unlock_target_sompi,
        pool.unlocked,
        pool.fee_recipients.len()
    ));
    for (index, recipient) in pool.fee_recipients.iter().enumerate() {
        out.push_str(&format!(
            " recipient[{index}]={{owner={} version={} payload_hex={} unclaimed={}}}",
            hex_lower(&recipient.owner_id),
            recipient.address_version,
            hex_lower(&recipient.address_payload),
            recipient.unclaimed_sompi
        ));
    }
    out.push('}');
    out
}

fn apply_root_leaf(buckets: &mut [[u8; 32]; ATOMIC_ROOT_BUCKETS], logical_key: &[u8], value: &[u8]) {
    let leaf_hash = root_leaf_hash(logical_key, value);
    let bucket_index = root_bucket_index(logical_key);
    xor_hash(&mut buckets[bucket_index], leaf_hash);
}

fn root_value_for_u64(value: u64) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

fn root_value_for_u128(value: u128) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

fn token_asset_class_tag(asset_class: &crate::state::TokenAssetClass) -> u8 {
    match asset_class {
        crate::state::TokenAssetClass::Standard => 0,
        crate::state::TokenAssetClass::Liquidity => 1,
    }
}

fn push_root_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn push_root_option_hash(out: &mut Vec<u8>, value: &Option<BlockHash>) {
    match value {
        Some(hash) => {
            out.push(1);
            out.extend_from_slice(&hash.as_bytes());
        }
        None => out.push(0),
    }
}

fn push_root_option_u64(out: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            out.push(1);
            out.extend_from_slice(&value.to_le_bytes());
        }
        None => out.push(0),
    }
}

fn root_value_for_asset(asset: &TokenAsset) -> Vec<u8> {
    let mut out = Vec::with_capacity(256 + asset.name.len() + asset.symbol.len() + asset.metadata.len() + asset.platform_tag.len());
    out.extend_from_slice(b"CAT_ASSET_ROOT_V5");
    out.extend_from_slice(&asset.asset_id);
    out.extend_from_slice(&asset.creator_owner_id);
    out.push(token_asset_class_tag(&asset.asset_class));
    out.push(asset.token_version);
    out.extend_from_slice(&asset.mint_authority_owner_id);
    out.push(asset.decimals);
    out.push(asset.supply_mode as u8);
    out.extend_from_slice(&asset.max_supply.to_le_bytes());
    out.extend_from_slice(&asset.total_supply.to_le_bytes());
    push_root_bytes(&mut out, &asset.name);
    push_root_bytes(&mut out, &asset.symbol);
    push_root_bytes(&mut out, &asset.metadata);
    push_root_bytes(&mut out, &asset.platform_tag);
    push_root_option_hash(&mut out, &asset.created_block_hash);
    push_root_option_u64(&mut out, asset.created_daa_score);
    push_root_option_u64(&mut out, asset.created_at);
    match asset.liquidity.as_ref() {
        Some(pool) => {
            out.push(1);
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
                push_root_bytes(&mut out, &recipient.address_payload);
                out.extend_from_slice(&recipient.unclaimed_sompi.to_le_bytes());
            }
            out.extend_from_slice(&pool.vault_outpoint.transaction_id.as_bytes());
            out.extend_from_slice(&pool.vault_outpoint.index.to_le_bytes());
            out.extend_from_slice(&pool.vault_value_sompi.to_le_bytes());
            out.extend_from_slice(&pool.unlock_target_sompi.to_le_bytes());
            out.push(u8::from(pool.unlocked));
        }
        None => out.push(0),
    }

    out
}

fn root_leaf_hash(logical_key: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bParams::new().hash_length(32).to_state();
    hasher.update(ROOT_LEAF_DOMAIN);
    hasher.update(&(logical_key.len() as u64).to_le_bytes());
    hasher.update(logical_key);
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_bytes());
    out
}

fn root_bucket_index(logical_key: &[u8]) -> usize {
    let mut hasher = Blake2bParams::new().hash_length(32).to_state();
    hasher.update(b"CRYPTIX_ATOMIC_V2_BUCKET_INDEX");
    hasher.update(logical_key);
    let digest = hasher.finalize();
    let bytes = digest.as_bytes();
    (((bytes[0] as usize) << 4) | ((bytes[1] as usize) >> 4)) & (ATOMIC_ROOT_BUCKETS - 1)
}

fn root_from_buckets(buckets: &[[u8; 32]; ATOMIC_ROOT_BUCKETS]) -> [u8; 32] {
    let mut hasher = Blake2bParams::new().hash_length(32).to_state();
    hasher.update(ROOT_BUCKET_DOMAIN);
    hasher.update(&(ATOMIC_ROOT_BUCKETS as u64).to_le_bytes());
    for bucket in buckets {
        hasher.update(bucket);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_bytes());
    out
}

fn xor_hash(target: &mut [u8; 32], value: [u8; 32]) {
    for (target, value) in target.iter_mut().zip(value) {
        *target ^= value;
    }
}

fn remove_archived_wal_dir(path: &Path) -> std::io::Result<()> {
    let archive_dir = path.join("archive");
    if archive_dir.exists() {
        std::fs::remove_dir_all(archive_dir)?;
    }
    Ok(())
}

fn decode_fixed_32(suffix: &[u8], label: &str) -> AtomicTokenResult<[u8; 32]> {
    if suffix.len() != 32 {
        return Err(AtomicTokenError::Processing(format!(
            "Atomic DB key decode failed for {label}: expected 32 bytes, got {}",
            suffix.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(suffix);
    Ok(out)
}

fn decode_block_hash(suffix: &[u8], label: &str) -> AtomicTokenResult<BlockHash> {
    Ok(BlockHash::from_bytes(decode_fixed_32(suffix, label)?))
}

fn decode_balance_key(suffix: &[u8]) -> AtomicTokenResult<BalanceKey> {
    if suffix.len() != 64 {
        return Err(AtomicTokenError::Processing(format!(
            "Atomic DB balance key decode failed: expected 64 bytes, got {}",
            suffix.len()
        )));
    }
    let mut asset_id = [0u8; 32];
    let mut owner_id = [0u8; 32];
    asset_id.copy_from_slice(&suffix[..32]);
    owner_id.copy_from_slice(&suffix[32..64]);
    Ok(BalanceKey { asset_id, owner_id })
}

fn decode_nonce_key(suffix: &[u8]) -> AtomicTokenResult<NonceKey> {
    if suffix.len() != 65 {
        return Err(AtomicTokenError::Processing(format!(
            "Atomic DB nonce key decode failed: expected 65 bytes, got {}",
            suffix.len()
        )));
    }
    let mut owner_id = [0u8; 32];
    let mut scope_id = [0u8; 32];
    owner_id.copy_from_slice(&suffix[..32]);
    scope_id.copy_from_slice(&suffix[33..65]);
    Ok(NonceKey { owner_id, scope_kind: suffix[32], scope_id })
}

fn decode_u64_suffix(suffix: &[u8], label: &str) -> AtomicTokenResult<u64> {
    if suffix.len() != 8 {
        return Err(AtomicTokenError::Processing(format!(
            "Atomic DB key decode failed for {label}: expected 8 bytes, got {}",
            suffix.len()
        )));
    }
    let mut out = [0u8; 8];
    out.copy_from_slice(suffix);
    Ok(u64::from_be_bytes(out))
}

fn decode_u16_suffix(suffix: &[u8], label: &str) -> AtomicTokenResult<u16> {
    if suffix.len() != 2 {
        return Err(AtomicTokenError::Processing(format!(
            "Atomic DB key decode failed for {label}: expected 2 bytes, got {}",
            suffix.len()
        )));
    }
    let mut out = [0u8; 2];
    out.copy_from_slice(suffix);
    Ok(u16::from_be_bytes(out))
}

fn decode_event_key_suffix(suffix: &[u8]) -> AtomicTokenResult<u64> {
    if suffix.len() != 40 {
        return Err(AtomicTokenError::Processing(format!(
            "Atomic DB event key decode failed: expected 40 bytes, got {}",
            suffix.len()
        )));
    }
    decode_u64_suffix(&suffix[..8], "event sequence")
}

#[cfg(test)]
mod tests {
    use super::AtomicStorageV2;
    use crate::{
        payload::{ApplyStatus, NoopReason, SupplyMode},
        state::{
            AtomicTokenState, BalanceKey, BlockJournal, LiquidityHolderAddressState, LiquidityPoolState, NonceKey, ProcessedOp,
            TokenAsset, TokenAssetClass,
        },
    };
    use cryptix_consensus_core::{tx::TransactionOutpoint, Hash as BlockHash};
    use std::{
        collections::HashMap,
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn unique_temp_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        std::env::temp_dir().join(format!("cryptix-atomic-{name}-{}-{nonce}", std::process::id()))
    }

    fn holder_address(marker: u8) -> LiquidityHolderAddressState {
        LiquidityHolderAddressState { address_version: 0, address_payload: vec![marker; 32] }
    }

    fn liquidity_asset(asset_id: [u8; 32], holders: Vec<([u8; 32], LiquidityHolderAddressState)>) -> TokenAsset {
        TokenAsset {
            asset_id,
            creator_owner_id: [1u8; 32],
            asset_class: TokenAssetClass::Liquidity,
            token_version: 1,
            mint_authority_owner_id: [2u8; 32],
            decimals: 8,
            supply_mode: SupplyMode::Capped,
            max_supply: 1_000_000,
            total_supply: 1_000,
            name: b"liquidity".to_vec(),
            symbol: b"LIQ".to_vec(),
            metadata: Vec::new(),
            platform_tag: Vec::new(),
            created_block_hash: None,
            created_daa_score: None,
            created_at: None,
            liquidity: Some(LiquidityPoolState {
                pool_nonce: 1,
                curve_version: 1,
                curve_mode: 0,
                individual_virtual_cpay_reserves_sompi: 0,
                individual_virtual_token_multiplier_bps: 0,
                real_cpay_reserves_sompi: 1,
                real_token_reserves: 1,
                virtual_cpay_reserves_sompi: 1,
                virtual_token_reserves: 1,
                unclaimed_fee_total_sompi: 0,
                fee_bps: 0,
                fee_recipients: Vec::new(),
                vault_outpoint: TransactionOutpoint { transaction_id: BlockHash::from_bytes(asset_id), index: asset_id[0] as u32 },
                vault_value_sompi: 1,
                unlock_target_sompi: 0,
                unlocked: true,
                holder_addresses: holders.into_iter().collect::<HashMap<_, _>>(),
            }),
        }
    }

    #[test]
    fn initializes_schema_v2_metadata_and_roundtrips_split_state() {
        let dir = unique_temp_dir("roundtrip");
        let genesis_hash = BlockHash::from_u64_word(42);
        let store = AtomicStorageV2::open(&dir, 6, "cryptix-simnet".to_string(), genesis_hash).expect("open store");
        assert!(store.load_state().expect("load empty").is_none());

        let asset_id = [7u8; 32];
        let owner_id = [9u8; 32];
        let mut state = AtomicTokenState::new(6, "cryptix-simnet".to_string());
        state.live_correct = true;
        state.degraded = true;
        state.balances.insert(BalanceKey { asset_id, owner_id }, 123);
        state.nonces.insert(NonceKey::asset(owner_id, asset_id), 8);
        state.anchor_counts.insert(owner_id, 1);
        state.applied_chain_order.push(BlockHash::from_u64_word(99));
        state.state_hash_by_block.insert(BlockHash::from_u64_word(99), state.compute_state_hash());

        store.persist_state(&state).expect("persist state");
        drop(store);

        let store = AtomicStorageV2::open(&dir, 6, "cryptix-simnet".to_string(), genesis_hash).expect("reopen store");
        let loaded = store.load_state().expect("load state").expect("state present");
        assert!(loaded.degraded);
        assert!(!loaded.live_correct);
        assert_eq!(loaded.balances.get(&BalanceKey { asset_id, owner_id }), Some(&123));
        assert_eq!(loaded.nonces.get(&NonceKey::asset(owner_id, asset_id)), Some(&8));
        assert_eq!(loaded.anchor_counts.get(&owner_id), Some(&1));
        assert_eq!(loaded.applied_chain_order, vec![BlockHash::from_u64_word(99)]);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn rejects_wrong_chain_metadata() {
        let dir = unique_temp_dir("wrong-chain");
        let genesis_hash = BlockHash::from_u64_word(1);
        let store = AtomicStorageV2::open(&dir, 6, "cryptix-simnet".to_string(), genesis_hash).expect("open store");
        drop(store);

        let err = match AtomicStorageV2::open(&dir, 6, "cryptix-mainnet".to_string(), genesis_hash) {
            Ok(_) => panic!("network mismatch must fail"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("Atomic DB chain mismatch"));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn delta_updates_current_root_without_full_rewrite() {
        let dir = unique_temp_dir("delta-root");
        let genesis_hash = BlockHash::from_u64_word(7);
        let store = AtomicStorageV2::open(&dir, 6, "cryptix-simnet".to_string(), genesis_hash).expect("open store");
        let asset_id = [3u8; 32];
        let owner_id = [4u8; 32];
        let balance_key = BalanceKey { asset_id, owner_id };

        let root_a = store
            .apply_current_state_delta(
                std::iter::empty(),
                [(balance_key, Some(50u128))],
                [(NonceKey::asset(owner_id, asset_id), Some(2u64))],
                [(owner_id, Some(1u64))],
                std::iter::empty(),
            )
            .expect("apply first delta");
        assert_eq!(store.get_balance(&balance_key).expect("balance"), 50);
        assert_eq!(store.current_root().expect("root"), Some(root_a));

        let root_b = store
            .apply_current_state_delta(
                std::iter::empty(),
                [(balance_key, Some(75u128))],
                std::iter::empty(),
                std::iter::empty(),
                std::iter::empty(),
            )
            .expect("apply second delta");
        assert_ne!(root_a, root_b);
        assert_eq!(store.get_balance(&balance_key).expect("balance"), 75);

        let root_c = store
            .apply_current_state_delta(
                std::iter::empty(),
                [(balance_key, None)],
                std::iter::empty(),
                std::iter::empty(),
                std::iter::empty(),
            )
            .expect("delete balance");
        assert_ne!(root_b, root_c);
        assert_eq!(store.get_balance(&balance_key).expect("balance"), 0);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn zero_balance_delete_is_scoped_to_one_asset_owner_pair() {
        let dir = unique_temp_dir("balance-index-scope");
        let genesis_hash = BlockHash::from_u64_word(12);
        let store = AtomicStorageV2::open(&dir, 6, "cryptix-simnet".to_string(), genesis_hash).expect("open store");
        let asset_a = [0xA1; 32];
        let asset_b = [0xB2; 32];
        let shared_owner = [0xCC; 32];
        let key_a = BalanceKey { asset_id: asset_a, owner_id: shared_owner };
        let key_b = BalanceKey { asset_id: asset_b, owner_id: shared_owner };

        store
            .apply_current_state_delta(
                std::iter::empty(),
                [(key_a, Some(100u128)), (key_b, Some(200u128))],
                std::iter::empty(),
                std::iter::empty(),
                std::iter::empty(),
            )
            .expect("write balances");

        let mut owner_balances = store.balances_by_owner(&shared_owner).expect("owner balances");
        owner_balances.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(owner_balances, vec![(asset_a, 100), (asset_b, 200)]);
        assert_eq!(store.holders_by_asset(&asset_a).expect("asset A holders"), vec![(shared_owner, 100)]);
        assert_eq!(store.holders_by_asset(&asset_b).expect("asset B holders"), vec![(shared_owner, 200)]);

        store
            .apply_current_state_delta(std::iter::empty(), [(key_a, None)], std::iter::empty(), std::iter::empty(), std::iter::empty())
            .expect("delete only asset A balance");

        assert_eq!(store.get_balance(&key_a).expect("asset A balance removed"), 0);
        assert_eq!(store.get_balance(&key_b).expect("asset B balance preserved"), 200);
        assert_eq!(store.balances_by_owner(&shared_owner).expect("owner balance index"), vec![(asset_b, 200)]);
        assert!(store.holders_by_asset(&asset_a).expect("asset A holder index").is_empty());
        assert_eq!(store.holders_by_asset(&asset_b).expect("asset B holder index"), vec![(shared_owner, 200)]);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn replace_current_state_from_preserves_source_root_and_runtime_history() {
        let source_dir = unique_temp_dir("replace-current-source");
        let target_dir = unique_temp_dir("replace-current-target");
        let genesis_hash = BlockHash::from_u64_word(17);
        let source = AtomicStorageV2::open(&source_dir, 6, "cryptix-simnet".to_string(), genesis_hash).expect("open source");
        let target = AtomicStorageV2::open(&target_dir, 6, "cryptix-simnet".to_string(), genesis_hash).expect("open target");

        let asset_id = [17u8; 32];
        let owner_id = [18u8; 32];
        let key = BalanceKey { asset_id, owner_id };
        let block_hash = BlockHash::from_u64_word(1700);
        let mut source_state = AtomicTokenState::new(6, "cryptix-simnet".to_string());
        source_state.balances.insert(key, 55);
        source_state.nonces.insert(NonceKey::asset(owner_id, asset_id), 3);
        source_state.anchor_counts.insert(owner_id, 2);
        source_state.applied_chain_order.push(block_hash);
        source_state.state_hash_by_block.insert(block_hash, source_state.compute_state_hash());
        source_state.next_event_sequence = 7;
        source.persist_state(&source_state).expect("persist source");
        let source_root = source.current_root().expect("source root").expect("root present");

        let stale_key = BalanceKey { asset_id: [99u8; 32], owner_id: [98u8; 32] };
        let mut stale_target_state = AtomicTokenState::new(6, "cryptix-simnet".to_string());
        stale_target_state.balances.insert(stale_key, 123);
        target.persist_state(&stale_target_state).expect("persist stale target");

        let mut runtime_history = source_state.clone();
        runtime_history.clear_persistent_state_overlay();
        target.persist_state(&runtime_history).expect("persist runtime history");
        let copied_root = target.replace_current_state_from(&source, &runtime_history).expect("copy current state");

        assert_eq!(copied_root, source_root);
        assert_eq!(target.current_root().expect("target root"), Some(source_root));
        assert_eq!(target.get_balance(&key).expect("copied balance"), 55);
        assert_eq!(target.get_balance(&stale_key).expect("stale balance removed"), 0);
        assert_eq!(target.get_nonce(&NonceKey::asset(owner_id, asset_id)).expect("copied nonce"), 3);
        let runtime = target.load_runtime_state().expect("runtime load").expect("runtime present");
        assert_eq!(runtime.applied_chain_order, vec![block_hash]);
        assert_eq!(runtime.next_event_sequence, 7);
        assert!(runtime.balances.is_empty());

        let _ = fs::remove_dir_all(source_dir);
        let _ = fs::remove_dir_all(target_dir);
    }

    #[test]
    fn runtime_load_keeps_large_state_maps_on_disk() {
        let dir = unique_temp_dir("runtime-load");
        let genesis_hash = BlockHash::from_u64_word(8);
        let store = AtomicStorageV2::open(&dir, 6, "cryptix-simnet".to_string(), genesis_hash).expect("open store");
        let asset_id = [5u8; 32];
        let owner_id = [6u8; 32];
        let key = BalanceKey { asset_id, owner_id };
        let block_hash = BlockHash::from_u64_word(100);
        let mut state = AtomicTokenState::new(6, "cryptix-simnet".to_string());
        state.balances.insert(key, 900);
        state.applied_chain_order.push(block_hash);
        state.state_hash_by_block.insert(block_hash, state.compute_state_hash());

        store.persist_state(&state).expect("persist state");
        drop(store);

        let store = AtomicStorageV2::open(&dir, 6, "cryptix-simnet".to_string(), genesis_hash).expect("reopen store");
        let runtime_state = store.load_runtime_state().expect("runtime load").expect("state present");
        assert!(runtime_state.assets.is_empty());
        assert!(runtime_state.balances.is_empty());
        assert_eq!(runtime_state.applied_chain_order, vec![block_hash]);
        assert_eq!(store.get_balance(&key).expect("balance point read"), 900);
        assert_eq!(store.balances_by_owner(&owner_id).expect("owner index"), vec![(asset_id, 900)]);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn prune_history_keeps_chain_order_without_full_rewrite() {
        let dir = unique_temp_dir("chain-order-base");
        let genesis_hash = BlockHash::from_u64_word(13);
        let store = AtomicStorageV2::open(&dir, 6, "cryptix-simnet".to_string(), genesis_hash).expect("open store");
        let first = BlockHash::from_u64_word(1);
        let second = BlockHash::from_u64_word(2);
        let third = BlockHash::from_u64_word(3);
        let fourth = BlockHash::from_u64_word(4);
        let pruned_txid = BlockHash::from_u64_word(1001);

        let mut state = AtomicTokenState::new(6, "cryptix-simnet".to_string());
        state.applied_chain_order.extend([first, second, third]);
        state.processed_ops.insert(
            pruned_txid,
            ProcessedOp { accepting_block_hash: first, apply_status: ApplyStatus::Applied, noop_reason: NoopReason::None },
        );
        for block_hash in state.applied_chain_order.iter().copied() {
            state.state_hash_by_block.insert(block_hash, state.compute_state_hash());
        }
        store.persist_state(&state).expect("persist state");

        store.prune_history(&[first, second], &[pruned_txid], &[third], None).expect("prune history");
        let runtime = store.load_runtime_state().expect("runtime load after prune").expect("state present");
        assert_eq!(runtime.applied_chain_order, vec![third]);
        assert!(store.get_processed_op(&pruned_txid).expect("processed op lookup").is_none());

        store
            .commit_applied_block_delta(
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                fourth,
                &BlockJournal::default(),
                1,
                0,
                &[],
                false,
                0,
            )
            .expect("append after prune");

        let runtime = store.load_runtime_state().expect("runtime load after append").expect("state present");
        assert_eq!(runtime.applied_chain_order, vec![third, fourth]);

        let mut chain_order = Vec::new();
        store
            .visit_all_chain_order(|index, block_hash| {
                chain_order.push((index, block_hash));
                Ok(())
            })
            .expect("visit chain order");
        assert_eq!(chain_order, vec![(0, third), (1, fourth)]);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn persist_state_does_not_materialize_default_nonce() {
        let dir = unique_temp_dir("default-nonce");
        let genesis_hash = BlockHash::from_u64_word(11);
        let store = AtomicStorageV2::open(&dir, 6, "cryptix-simnet".to_string(), genesis_hash).expect("open store");
        let asset_id = [11u8; 32];
        let owner_id = [12u8; 32];
        let nonce_key = NonceKey::asset(owner_id, asset_id);
        store.persist_state(&AtomicTokenState::new(6, "cryptix-simnet".to_string())).expect("persist empty state");
        let empty_root = store.current_root().expect("empty root").expect("empty root present");

        let mut state = AtomicTokenState::new(6, "cryptix-simnet".to_string());
        state.nonces.insert(nonce_key, 1);

        store.persist_state(&state).expect("persist state");

        assert_eq!(store.get_nonce(&nonce_key).expect("nonce"), 1);
        assert_eq!(store.current_root().expect("root"), Some(empty_root));
        assert_eq!(store.prefix_count(super::PREFIX_NONCE).expect("nonce count"), 0);
        let runtime_state = store.load_runtime_state().expect("load runtime").expect("state present");
        assert!(runtime_state.nonces.is_empty());

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn asset_delta_removes_stale_known_owner_address_index() {
        let dir = unique_temp_dir("known-owner-remove");
        let genesis_hash = BlockHash::from_u64_word(9);
        let store = AtomicStorageV2::open(&dir, 6, "cryptix-simnet".to_string(), genesis_hash).expect("open store");
        let asset_id = [9u8; 32];
        let old_owner = [11u8; 32];
        let new_owner = [12u8; 32];

        store
            .apply_current_state_delta(
                [(asset_id, Some(liquidity_asset(asset_id, vec![(old_owner, holder_address(0x11))])))],
                std::iter::empty(),
                std::iter::empty(),
                std::iter::empty(),
                std::iter::empty(),
            )
            .expect("write initial asset");
        assert_eq!(store.get_known_owner_address(&old_owner).expect("old owner"), Some(holder_address(0x11)));

        store
            .apply_current_state_delta(
                [(asset_id, Some(liquidity_asset(asset_id, vec![(new_owner, holder_address(0x12))])))],
                std::iter::empty(),
                std::iter::empty(),
                std::iter::empty(),
                std::iter::empty(),
            )
            .expect("replace asset holders");
        assert_eq!(store.get_known_owner_address(&old_owner).expect("old owner removed"), None);
        assert_eq!(store.get_known_owner_address(&new_owner).expect("new owner"), Some(holder_address(0x12)));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn asset_delta_preserves_known_owner_address_from_other_asset() {
        let dir = unique_temp_dir("known-owner-shared");
        let genesis_hash = BlockHash::from_u64_word(10);
        let store = AtomicStorageV2::open(&dir, 6, "cryptix-simnet".to_string(), genesis_hash).expect("open store");
        let asset_a = [13u8; 32];
        let asset_b = [14u8; 32];
        let shared_owner = [15u8; 32];

        store
            .apply_current_state_delta(
                [
                    (asset_a, Some(liquidity_asset(asset_a, vec![(shared_owner, holder_address(0x13))]))),
                    (asset_b, Some(liquidity_asset(asset_b, vec![(shared_owner, holder_address(0x14))]))),
                ],
                std::iter::empty(),
                std::iter::empty(),
                std::iter::empty(),
                std::iter::empty(),
            )
            .expect("write assets");
        assert!(store.get_known_owner_address(&shared_owner).expect("shared owner").is_some());

        store
            .apply_current_state_delta(
                [(asset_b, None)],
                std::iter::empty(),
                std::iter::empty(),
                std::iter::empty(),
                std::iter::empty(),
            )
            .expect("delete one asset");
        assert_eq!(store.get_known_owner_address(&shared_owner).expect("shared owner preserved"), Some(holder_address(0x13)));

        let _ = fs::remove_dir_all(dir);
    }
}
