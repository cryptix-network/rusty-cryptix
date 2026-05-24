use cryptix_consensus_core::block::{BlockTemplate, VirtualStateApproxId};
use cryptix_core::time::unix_now;
use parking_lot::{Mutex, MutexGuard};
use std::sync::Arc;

/// CACHE_LIFETIME indicates the default duration in milliseconds after which the cached data expires.
const DEFAULT_CACHE_LIFETIME: u64 = 1_000;

pub(crate) struct Inner {
    /// Time, in milliseconds, at which the cache was last updated
    last_update_time: u64,

    /// The optional template
    block_template: Option<Arc<BlockTemplate>>,

    /// Duration in milliseconds after which the cached data expires
    cache_lifetime: u64,
}

impl Inner {
    pub(crate) fn new(cache_lifetime: Option<u64>) -> Self {
        let cache_lifetime = cache_lifetime.unwrap_or(DEFAULT_CACHE_LIFETIME);
        Self { last_update_time: 0, block_template: None, cache_lifetime }
    }

    fn clear(&mut self) {
        self.block_template = None;
    }

    pub(crate) fn get_immutable_cached_template(&self) -> Option<Arc<BlockTemplate>> {
        let now = unix_now();
        // We verify that `now > last update` in order to avoid theoretic clock change bugs
        if now > self.last_update_time + self.cache_lifetime || now < self.last_update_time {
            None
        } else {
            self.block_template.clone()
        }
    }

    pub(crate) fn set_immutable_cached_template(&mut self, block_template: BlockTemplate) -> Arc<BlockTemplate> {
        self.last_update_time = unix_now();
        let block_template = Arc::new(block_template);
        self.block_template = Some(block_template.clone());
        block_template
    }
}

pub(crate) struct BlockTemplateCache {
    inner: Mutex<Inner>,
}

impl BlockTemplateCache {
    pub(crate) fn new(cache_lifetime: Option<u64>) -> Self {
        Self { inner: Mutex::new(Inner::new(cache_lifetime)) }
    }

    #[cfg(test)]
    pub(crate) fn clear(&self) {
        self.inner.lock().clear();
    }

    pub(crate) fn lock(&self, virtual_state_approx_id: VirtualStateApproxId) -> MutexGuard<Inner> {
        let mut guard = self.inner.lock();
        if guard.block_template.as_ref().is_some_and(|template| template.to_virtual_state_approx_id() != virtual_state_approx_id) {
            // If the VirtualStateApproxId is different from ours, our template is likely expired and we should clear it
            guard.clear();
        }
        guard
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptix_consensus_core::{
        block::MutableBlock, coinbase::MinerData, constants::BLOCK_VERSION, header::Header, tx::ScriptPublicKey,
    };
    use cryptix_hashes::{Hash, ZERO_HASH};

    fn hash(byte: u8) -> Hash {
        Hash::from_bytes([byte; 32])
    }

    fn state_id(parents_byte: u8, raw_utxo_byte: u8, atomic_byte: u8, accepted_byte: u8) -> VirtualStateApproxId {
        VirtualStateApproxId::new(
            42,
            7.into(),
            hash(1),
            hash(parents_byte),
            hash(raw_utxo_byte),
            hash(atomic_byte),
            hash(accepted_byte),
        )
    }

    fn template(state_id: VirtualStateApproxId) -> BlockTemplate {
        let header =
            Header::new_finalized(BLOCK_VERSION, vec![], ZERO_HASH, ZERO_HASH, ZERO_HASH, 1, 0, 0, 42, 7.into(), 0, ZERO_HASH);
        BlockTemplate::new(
            MutableBlock::new(header, vec![]),
            MinerData::new(ScriptPublicKey::from_vec(0, vec![]), vec![]),
            false,
            0,
            0,
            hash(1),
            state_id,
            vec![],
        )
    }

    #[test]
    fn cache_lock_expires_template_when_virtual_state_identity_changes() {
        for changed_id in [state_id(9, 2, 3, 4), state_id(8, 9, 3, 4), state_id(8, 2, 9, 4), state_id(8, 2, 3, 9)] {
            let cache = BlockTemplateCache::new(Some(u64::MAX / 2));
            let original_id = state_id(8, 2, 3, 4);

            {
                let mut guard = cache.lock(original_id.clone());
                guard.set_immutable_cached_template(template(original_id));
                assert!(guard.get_immutable_cached_template().is_some());
            }

            let guard = cache.lock(changed_id);
            assert!(guard.get_immutable_cached_template().is_none());
        }
    }
}
