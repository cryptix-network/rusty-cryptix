use cryptix_hashes::Hash as BlockHash;
use cryptix_rpc_core::{RpcBlock, RpcHeader, RpcTransaction};
use std::{collections::HashMap, mem::size_of, sync::Mutex};

const MILLIS_PER_DAY: f64 = 86_400_000.0;
const HEADER_BASE_BYTES: u64 = 512;
const BLOCK_BASE_BYTES: u64 = 1024;
const TRANSACTION_BASE_BYTES: u64 = 256;
const INPUT_BASE_BYTES: u64 = 160;
const OUTPUT_BASE_BYTES: u64 = 120;
const HASH_BYTES: u64 = 32;
const SELECTED_PARENT_LINK_BYTES: u64 = 128;
const EVICT_TARGET_PERCENT: u64 = 95;

#[derive(Clone, Copy, Debug)]
pub struct RpcBlockScanCacheConfig {
    pub enabled: bool,
    pub days: f64,
    pub max_bytes: u64,
}

impl RpcBlockScanCacheConfig {
    pub fn new(enabled: bool, days: f64, max_bytes: u64) -> Self {
        let days = if days.is_finite() { days.clamp(0.1, 7.0) } else { 1.0 };
        Self { enabled, days, max_bytes }
    }

    pub fn max_age_ms(self) -> u64 {
        (self.days * MILLIS_PER_DAY).round() as u64
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct BlockCacheKey {
    hash: BlockHash,
    include_transactions: bool,
}

#[derive(Clone, Debug)]
struct CacheEntry<T> {
    value: T,
    timestamp_ms: u64,
    estimated_bytes: u64,
    last_access_seq: u64,
}

#[derive(Debug, Default)]
struct CacheInner {
    headers: HashMap<BlockHash, CacheEntry<RpcHeader>>,
    blocks: HashMap<BlockCacheKey, CacheEntry<RpcBlock>>,
    selected_parents: HashMap<BlockHash, CacheEntry<BlockHash>>,
    current_bytes: u64,
    access_seq: u64,
    serving: bool,
    activity: RpcBlockScanCacheActivity,
}

#[derive(Debug)]
pub struct RpcBlockScanCache {
    config: RpcBlockScanCacheConfig,
    inner: Mutex<CacheInner>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RpcBlockScanCacheStats {
    pub headers: usize,
    pub blocks: usize,
    pub selected_parent_links: usize,
    pub current_bytes: u64,
    pub max_bytes: u64,
    pub serving: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RpcBlockScanCacheActivity {
    pub added_headers: u64,
    pub added_blocks: u64,
    pub added_selected_parent_links: u64,
    pub removed_headers: u64,
    pub removed_blocks: u64,
    pub removed_selected_parent_links: u64,
    pub added_bytes: u64,
    pub removed_bytes: u64,
}

impl RpcBlockScanCacheActivity {
    pub fn saturating_sub(self, previous: Self) -> Self {
        Self {
            added_headers: self.added_headers.saturating_sub(previous.added_headers),
            added_blocks: self.added_blocks.saturating_sub(previous.added_blocks),
            added_selected_parent_links: self.added_selected_parent_links.saturating_sub(previous.added_selected_parent_links),
            removed_headers: self.removed_headers.saturating_sub(previous.removed_headers),
            removed_blocks: self.removed_blocks.saturating_sub(previous.removed_blocks),
            removed_selected_parent_links: self.removed_selected_parent_links.saturating_sub(previous.removed_selected_parent_links),
            added_bytes: self.added_bytes.saturating_sub(previous.added_bytes),
            removed_bytes: self.removed_bytes.saturating_sub(previous.removed_bytes),
        }
    }
}

impl RpcBlockScanCache {
    pub fn new(config: RpcBlockScanCacheConfig) -> Self {
        Self { config, inner: Mutex::new(CacheInner::default()) }
    }

    pub fn enabled(&self) -> bool {
        self.config.enabled && self.config.max_bytes > 0
    }

    pub fn days(&self) -> f64 {
        self.config.days
    }

    pub fn max_bytes(&self) -> u64 {
        self.config.max_bytes
    }

    pub fn max_age_ms(&self) -> u64 {
        self.config.max_age_ms()
    }

    pub fn stats(&self) -> RpcBlockScanCacheStats {
        let inner = self.inner.lock().expect("RPC block scan cache mutex poisoned");
        RpcBlockScanCacheStats {
            headers: inner.headers.len(),
            blocks: inner.blocks.len(),
            selected_parent_links: inner.selected_parents.len(),
            current_bytes: inner.current_bytes,
            max_bytes: self.config.max_bytes,
            serving: inner.serving,
        }
    }

    pub fn activity_snapshot(&self) -> RpcBlockScanCacheActivity {
        let inner = self.inner.lock().expect("RPC block scan cache mutex poisoned");
        inner.activity
    }

    pub fn is_serving(&self) -> bool {
        if !self.enabled() {
            return false;
        }
        let inner = self.inner.lock().expect("RPC block scan cache mutex poisoned");
        inner.serving
    }

    pub fn mark_ready_to_serve(&self) {
        if !self.enabled() {
            return;
        }
        let mut inner = self.inner.lock().expect("RPC block scan cache mutex poisoned");
        inner.serving = true;
    }

    pub fn is_near_full(&self) -> bool {
        if !self.enabled() {
            return true;
        }
        let inner = self.inner.lock().expect("RPC block scan cache mutex poisoned");
        inner.current_bytes >= self.config.max_bytes.saturating_mul(EVICT_TARGET_PERCENT).saturating_div(100)
    }

    pub fn contains_header(&self, hash: BlockHash, now_ms: u64) -> bool {
        self.get_header(hash, now_ms).is_some()
    }

    pub fn contains_block(&self, hash: BlockHash, include_transactions: bool, now_ms: u64) -> bool {
        if !self.is_serving() {
            return false;
        }
        let mut inner = self.inner.lock().expect("RPC block scan cache mutex poisoned");
        let key = BlockCacheKey { hash, include_transactions };
        let Some(entry) = inner.blocks.get(&key) else {
            return false;
        };
        if self.is_expired(entry.timestamp_ms, now_ms) {
            inner.remove_block(key);
            return false;
        }
        true
    }

    pub fn get_header(&self, hash: BlockHash, now_ms: u64) -> Option<RpcHeader> {
        if !self.is_serving() {
            return None;
        }

        let mut inner = self.inner.lock().expect("RPC block scan cache mutex poisoned");
        let Some(entry) = inner.headers.get(&hash) else {
            return None;
        };
        if self.is_expired(entry.timestamp_ms, now_ms) {
            inner.remove_header(hash);
            return None;
        }

        let seq = inner.next_access_seq();
        let entry = inner.headers.get_mut(&hash)?;
        entry.last_access_seq = seq;
        Some(entry.value.clone())
    }

    pub fn get_selected_parent(&self, hash: BlockHash, now_ms: u64) -> Option<BlockHash> {
        if !self.is_serving() {
            return None;
        }

        let mut inner = self.inner.lock().expect("RPC block scan cache mutex poisoned");
        let Some(entry) = inner.selected_parents.get(&hash) else {
            return None;
        };
        if self.is_expired(entry.timestamp_ms, now_ms) {
            inner.remove_selected_parent(hash);
            return None;
        }

        let seq = inner.next_access_seq();
        let entry = inner.selected_parents.get_mut(&hash)?;
        entry.last_access_seq = seq;
        Some(entry.value)
    }

    pub fn insert_header(&self, header: RpcHeader, now_ms: u64) -> bool {
        if !self.enabled() || !self.is_recent(header.timestamp, now_ms) {
            return false;
        }

        let estimated_bytes = estimate_header_bytes(&header);
        if estimated_bytes > self.config.max_bytes {
            return false;
        }

        let mut inner = self.inner.lock().expect("RPC block scan cache mutex poisoned");
        let seq = inner.next_access_seq();
        let hash = header.hash;
        let timestamp_ms = header.timestamp;
        let had_previous = if let Some(previous) = inner.headers.remove(&hash) {
            inner.current_bytes = inner.current_bytes.saturating_sub(previous.estimated_bytes);
            true
        } else {
            false
        };
        inner.current_bytes = inner.current_bytes.saturating_add(estimated_bytes);
        inner.headers.insert(hash, CacheEntry { value: header, timestamp_ms, estimated_bytes, last_access_seq: seq });
        self.enforce_limits(&mut inner, now_ms);
        let retained = inner.headers.contains_key(&hash);
        if retained && !had_previous {
            inner.activity.added_headers = inner.activity.added_headers.saturating_add(1);
            inner.activity.added_bytes = inner.activity.added_bytes.saturating_add(estimated_bytes);
        }
        retained
    }

    pub fn insert_selected_parent(&self, hash: BlockHash, selected_parent: BlockHash, timestamp_ms: u64, now_ms: u64) -> bool {
        if !self.enabled() || !self.is_recent(timestamp_ms, now_ms) || SELECTED_PARENT_LINK_BYTES > self.config.max_bytes {
            return false;
        }

        let mut inner = self.inner.lock().expect("RPC block scan cache mutex poisoned");
        let seq = inner.next_access_seq();
        let had_previous = if let Some(previous) = inner.selected_parents.remove(&hash) {
            inner.current_bytes = inner.current_bytes.saturating_sub(previous.estimated_bytes);
            true
        } else {
            false
        };
        inner.current_bytes = inner.current_bytes.saturating_add(SELECTED_PARENT_LINK_BYTES);
        inner.selected_parents.insert(
            hash,
            CacheEntry { value: selected_parent, timestamp_ms, estimated_bytes: SELECTED_PARENT_LINK_BYTES, last_access_seq: seq },
        );
        self.enforce_limits(&mut inner, now_ms);
        let retained = inner.selected_parents.contains_key(&hash);
        if retained && !had_previous {
            inner.activity.added_selected_parent_links = inner.activity.added_selected_parent_links.saturating_add(1);
            inner.activity.added_bytes = inner.activity.added_bytes.saturating_add(SELECTED_PARENT_LINK_BYTES);
        }
        retained
    }

    pub fn get_block(&self, hash: BlockHash, include_transactions: bool, now_ms: u64) -> Option<RpcBlock> {
        if !self.is_serving() {
            return None;
        }

        let mut inner = self.inner.lock().expect("RPC block scan cache mutex poisoned");
        let key = BlockCacheKey { hash, include_transactions };
        if let Some(block) = self.get_block_locked(&mut inner, key, now_ms) {
            return Some(block);
        }

        if !include_transactions {
            let full_key = BlockCacheKey { hash, include_transactions: true };
            if let Some(mut block) = self.get_block_locked(&mut inner, full_key, now_ms) {
                block.transactions.clear();
                return Some(block);
            }
        }

        None
    }

    pub fn insert_block(&self, block: RpcBlock, include_transactions: bool, now_ms: u64) -> bool {
        if !self.enabled() || !self.is_recent(block.header.timestamp, now_ms) {
            return false;
        }

        let estimated_bytes = estimate_block_bytes(&block, include_transactions);
        if estimated_bytes > self.config.max_bytes {
            return false;
        }

        self.insert_header(block.header.clone(), now_ms);

        let mut inner = self.inner.lock().expect("RPC block scan cache mutex poisoned");
        let seq = inner.next_access_seq();
        let key = BlockCacheKey { hash: block.header.hash, include_transactions };
        let timestamp_ms = block.header.timestamp;
        let had_previous = if let Some(previous) = inner.blocks.remove(&key) {
            inner.current_bytes = inner.current_bytes.saturating_sub(previous.estimated_bytes);
            true
        } else {
            false
        };
        inner.current_bytes = inner.current_bytes.saturating_add(estimated_bytes);
        inner.blocks.insert(key, CacheEntry { value: block, timestamp_ms, estimated_bytes, last_access_seq: seq });
        self.enforce_limits(&mut inner, now_ms);
        let retained = inner.blocks.contains_key(&key);
        if retained && !had_previous {
            inner.activity.added_blocks = inner.activity.added_blocks.saturating_add(1);
            inner.activity.added_bytes = inner.activity.added_bytes.saturating_add(estimated_bytes);
        }
        retained
    }

    fn get_block_locked(&self, inner: &mut CacheInner, key: BlockCacheKey, now_ms: u64) -> Option<RpcBlock> {
        let Some(entry) = inner.blocks.get(&key) else {
            return None;
        };
        if self.is_expired(entry.timestamp_ms, now_ms) {
            inner.remove_block(key);
            return None;
        }

        let seq = inner.next_access_seq();
        let entry = inner.blocks.get_mut(&key)?;
        entry.last_access_seq = seq;
        Some(entry.value.clone())
    }

    fn enforce_limits(&self, inner: &mut CacheInner, now_ms: u64) {
        #[derive(Clone, Copy)]
        enum EvictionTarget {
            Header(BlockHash),
            Block(BlockCacheKey),
            SelectedParent(BlockHash),
        }

        inner.remove_expired(now_ms, self.config.max_age_ms());
        if inner.current_bytes <= self.config.max_bytes {
            return;
        }

        let target_bytes = self.config.max_bytes.saturating_mul(EVICT_TARGET_PERCENT).saturating_div(100);
        while inner.current_bytes > target_bytes {
            let mut candidate: Option<(u64, u64, EvictionTarget)> = None;
            for (hash, entry) in inner.headers.iter() {
                let candidate_key = (entry.timestamp_ms, entry.last_access_seq, EvictionTarget::Header(*hash));
                if candidate.map_or(true, |(timestamp_ms, seq, _)| (entry.timestamp_ms, entry.last_access_seq) < (timestamp_ms, seq)) {
                    candidate = Some(candidate_key);
                }
            }
            for (key, entry) in inner.blocks.iter() {
                let candidate_key = (entry.timestamp_ms, entry.last_access_seq, EvictionTarget::Block(*key));
                if candidate.map_or(true, |(timestamp_ms, seq, _)| (entry.timestamp_ms, entry.last_access_seq) < (timestamp_ms, seq)) {
                    candidate = Some(candidate_key);
                }
            }
            for (hash, entry) in inner.selected_parents.iter() {
                let candidate_key = (entry.timestamp_ms, entry.last_access_seq, EvictionTarget::SelectedParent(*hash));
                if candidate.map_or(true, |(timestamp_ms, seq, _)| (entry.timestamp_ms, entry.last_access_seq) < (timestamp_ms, seq)) {
                    candidate = Some(candidate_key);
                }
            }

            match candidate.map(|(_, _, target)| target) {
                Some(EvictionTarget::Header(hash)) => inner.remove_header(hash),
                Some(EvictionTarget::Block(key)) => inner.remove_block(key),
                Some(EvictionTarget::SelectedParent(hash)) => inner.remove_selected_parent(hash),
                None => break,
            }
        }
    }

    fn is_recent(&self, timestamp_ms: u64, now_ms: u64) -> bool {
        !self.is_expired(timestamp_ms, now_ms)
    }

    fn is_expired(&self, timestamp_ms: u64, now_ms: u64) -> bool {
        now_ms.saturating_sub(timestamp_ms) > self.config.max_age_ms()
    }
}

impl CacheInner {
    fn next_access_seq(&mut self) -> u64 {
        self.access_seq = self.access_seq.saturating_add(1);
        self.access_seq
    }

    fn remove_header(&mut self, hash: BlockHash) {
        if let Some(entry) = self.headers.remove(&hash) {
            self.current_bytes = self.current_bytes.saturating_sub(entry.estimated_bytes);
            self.activity.removed_headers = self.activity.removed_headers.saturating_add(1);
            self.activity.removed_bytes = self.activity.removed_bytes.saturating_add(entry.estimated_bytes);
        }
    }

    fn remove_block(&mut self, key: BlockCacheKey) {
        if let Some(entry) = self.blocks.remove(&key) {
            self.current_bytes = self.current_bytes.saturating_sub(entry.estimated_bytes);
            self.activity.removed_blocks = self.activity.removed_blocks.saturating_add(1);
            self.activity.removed_bytes = self.activity.removed_bytes.saturating_add(entry.estimated_bytes);
        }
    }

    fn remove_selected_parent(&mut self, hash: BlockHash) {
        if let Some(entry) = self.selected_parents.remove(&hash) {
            self.current_bytes = self.current_bytes.saturating_sub(entry.estimated_bytes);
            self.activity.removed_selected_parent_links = self.activity.removed_selected_parent_links.saturating_add(1);
            self.activity.removed_bytes = self.activity.removed_bytes.saturating_add(entry.estimated_bytes);
        }
    }

    fn remove_expired(&mut self, now_ms: u64, max_age_ms: u64) {
        let expired_headers = self
            .headers
            .iter()
            .filter_map(|(hash, entry)| (now_ms.saturating_sub(entry.timestamp_ms) > max_age_ms).then_some(*hash))
            .collect::<Vec<_>>();
        for hash in expired_headers {
            self.remove_header(hash);
        }

        let expired_selected_parents = self
            .selected_parents
            .iter()
            .filter_map(|(hash, entry)| (now_ms.saturating_sub(entry.timestamp_ms) > max_age_ms).then_some(*hash))
            .collect::<Vec<_>>();
        for hash in expired_selected_parents {
            self.remove_selected_parent(hash);
        }

        let expired_blocks = self
            .blocks
            .iter()
            .filter_map(|(key, entry)| (now_ms.saturating_sub(entry.timestamp_ms) > max_age_ms).then_some(*key))
            .collect::<Vec<_>>();
        for key in expired_blocks {
            self.remove_block(key);
        }
    }
}

fn estimate_header_bytes(header: &RpcHeader) -> u64 {
    let parents = header.parents_by_level.iter().map(|level| level.len() as u64 * HASH_BYTES + 24).sum::<u64>();
    HEADER_BASE_BYTES + parents + size_of::<RpcHeader>() as u64
}

fn estimate_block_bytes(block: &RpcBlock, include_transactions: bool) -> u64 {
    let verbose_bytes = block.verbose_data.as_ref().map_or(0, |verbose| {
        256 + verbose.transaction_ids.len() as u64 * HASH_BYTES
            + verbose.children_hashes.len() as u64 * HASH_BYTES
            + verbose.merge_set_blues_hashes.len() as u64 * HASH_BYTES
            + verbose.merge_set_reds_hashes.len() as u64 * HASH_BYTES
    });
    let transactions =
        include_transactions.then(|| block.transactions.iter().map(estimate_transaction_bytes).sum::<u64>()).unwrap_or(0);

    BLOCK_BASE_BYTES + estimate_header_bytes(&block.header) + verbose_bytes + transactions
}

fn estimate_transaction_bytes(transaction: &RpcTransaction) -> u64 {
    let inputs = transaction.inputs.iter().map(|input| INPUT_BASE_BYTES + input.signature_script.len() as u64).sum::<u64>();
    let outputs =
        transaction.outputs.iter().map(|output| OUTPUT_BASE_BYTES + output.script_public_key.script().len() as u64).sum::<u64>();
    TRANSACTION_BASE_BYTES + inputs + outputs + transaction.payload.len() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptix_consensus_core::BlueWorkType;
    use cryptix_hashes::Hash;

    fn header(id: u64, timestamp_ms: u64) -> RpcHeader {
        RpcHeader {
            hash: Hash::from_u64_word(id),
            version: 0,
            parents_by_level: vec![vec![Hash::from_u64_word(id.saturating_sub(1))]],
            hash_merkle_root: Hash::from_u64_word(id + 10),
            accepted_id_merkle_root: Hash::from_u64_word(id + 20),
            utxo_commitment: Hash::from_u64_word(id + 30),
            timestamp: timestamp_ms,
            bits: 0,
            nonce: 0,
            daa_score: id,
            blue_work: BlueWorkType::from(0u64),
            blue_score: id,
            pruning_point: Hash::from_u64_word(1),
        }
    }

    fn ready_cache(days: f64, max_bytes: u64) -> RpcBlockScanCache {
        let cache = RpcBlockScanCache::new(RpcBlockScanCacheConfig::new(true, days, max_bytes));
        cache.mark_ready_to_serve();
        cache
    }

    #[test]
    fn disabled_cache_is_noop() {
        let cache = RpcBlockScanCache::new(RpcBlockScanCacheConfig::new(false, 1.0, 1024 * 1024));
        let now = 1_000_000;
        let header = header(1, now);
        cache.insert_header(header.clone(), now);

        assert!(cache.get_header(header.hash, now).is_none());
    }

    #[test]
    fn cache_does_not_serve_until_marked_ready() {
        let cache = RpcBlockScanCache::new(RpcBlockScanCacheConfig::new(true, 1.0, 1024 * 1024));
        let now = 5_000_000;
        let header = header(1, now);
        cache.insert_header(header.clone(), now);

        assert!(!cache.is_serving());
        assert!(cache.get_header(header.hash, now).is_none());

        cache.mark_ready_to_serve();
        assert!(cache.is_serving());
        assert_eq!(cache.get_header(header.hash, now).unwrap().hash, header.hash);
    }

    #[test]
    fn recent_header_round_trips_and_expires() {
        let cache = ready_cache(0.1, 1024 * 1024);
        let now = 10_000_000;
        let header = header(2, now);
        cache.insert_header(header.clone(), now);

        assert_eq!(cache.get_header(header.hash, now).unwrap().hash, header.hash);
        assert!(cache.get_header(header.hash, now + 9_000_000).is_none());
    }

    #[test]
    fn old_header_is_not_inserted() {
        let cache = ready_cache(0.1, 1024 * 1024);
        let now = 20_000_000;
        let header = header(4, now - cache.max_age_ms() - 1);
        cache.insert_header(header.clone(), now);

        assert!(cache.get_header(header.hash, now).is_none());
        assert_eq!(cache.stats().headers, 0);
    }

    #[test]
    fn selected_parent_links_round_trip_expire_and_report_activity() {
        let cache = ready_cache(0.1, 1024 * 1024);
        let now = 25_000_000;
        let hash = Hash::from_u64_word(12);
        let selected_parent = Hash::from_u64_word(11);

        assert!(cache.insert_selected_parent(hash, selected_parent, now, now));
        assert_eq!(cache.get_selected_parent(hash, now), Some(selected_parent));
        let activity = cache.activity_snapshot();
        assert_eq!(activity.added_selected_parent_links, 1);

        assert!(cache.get_selected_parent(hash, now + 9_000_000).is_none());
        let activity = cache.activity_snapshot();
        assert_eq!(activity.removed_selected_parent_links, 1);
        assert_eq!(cache.stats().selected_parent_links, 0);
    }

    #[test]
    fn max_bytes_eviction_keeps_cache_bounded() {
        let cache = ready_cache(1.0, 4 * 1024);
        let now = 30_000_000;

        for id in 10..40 {
            cache.insert_block(RpcBlock { header: header(id, now), transactions: vec![], verbose_data: None }, true, now);
        }

        let stats = cache.stats();
        assert!(stats.current_bytes <= stats.max_bytes);
        assert!(stats.blocks < 30);
    }

    #[test]
    fn eviction_prefers_removing_older_blocks() {
        let cache = ready_cache(1.0, 4 * 1024);
        let now = 40_000_000;
        let newest = RpcBlock { header: header(100, now), transactions: vec![], verbose_data: None };
        let newest_hash = newest.header.hash;
        cache.insert_block(newest, true, now);

        for id in 101..120 {
            cache.insert_block(RpcBlock { header: header(id, now - id), transactions: vec![], verbose_data: None }, true, now);
        }

        assert!(cache.get_block(newest_hash, true, now).is_some());
        assert!(cache.stats().current_bytes <= cache.stats().max_bytes);
    }

    #[test]
    fn newer_block_displaces_older_block_when_cache_is_full() {
        let cache = ready_cache(1.0, 4 * 1024);
        let now = 45_000_000;
        for id in 1..20 {
            cache.insert_block(
                RpcBlock { header: header(id, now - 10_000 - id), transactions: vec![], verbose_data: None },
                true,
                now,
            );
        }
        let stats_before = cache.stats();
        assert!(stats_before.current_bytes <= stats_before.max_bytes);

        let newest = RpcBlock { header: header(200, now), transactions: vec![], verbose_data: None };
        let newest_hash = newest.header.hash;
        assert!(cache.insert_block(newest, true, now));

        assert!(cache.get_block(newest_hash, true, now).is_some());
        assert!(cache.stats().current_bytes <= cache.stats().max_bytes);
    }

    #[test]
    fn missing_or_evicted_block_returns_none_for_storage_fallback() {
        let cache = ready_cache(1.0, 2 * 1024);
        let now = 50_000_000;
        let first = RpcBlock { header: header(50, now), transactions: vec![], verbose_data: None };
        let first_hash = first.header.hash;
        cache.insert_block(first, true, now);

        for id in 51..60 {
            cache.insert_block(RpcBlock { header: header(id, now), transactions: vec![], verbose_data: None }, true, now);
        }

        if cache.get_block(first_hash, true, now).is_none() {
            assert!(!cache.contains_block(first_hash, true, now));
        }
        assert!(cache.get_block(Hash::from_u64_word(999), true, now).is_none());
    }

    #[test]
    fn full_block_can_serve_header_only_block_request() {
        let cache = ready_cache(1.0, 1024 * 1024);
        let now = 20_000_000;
        let block = RpcBlock { header: header(3, now), transactions: vec![], verbose_data: None };
        let hash = block.header.hash;
        cache.insert_block(block, true, now);

        let cached = cache.get_block(hash, false, now).unwrap();
        assert_eq!(cached.header.hash, hash);
        assert!(cached.transactions.is_empty());
    }
}
