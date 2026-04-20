use async_trait::async_trait;
use cryptix_consensus_core::tx::Transaction;
use cryptix_consensusmanager::ConsensusProxy;
use cryptix_hashes::Hash;
use cryptix_mining::manager::MiningManagerProxy;
use cryptix_p2p_lib::P2P_SERVICE_BIT_HFA;

// Service-bit advertised in VersionMessage.services when this node supports HF-A P2P relay.
pub const HFA_P2P_SERVICE_BIT: u64 = P2P_SERVICE_BIT_HFA;

// Hard bounds for P2P fast relay and pull-on-miss.
pub const HFA_MAX_INTENT_IDS_PER_MESSAGE: usize = 256;
pub const HFA_PULL_ON_MISS_MAX_RETRIES: usize = 2;
pub const HFA_PULL_ON_MISS_WAIT_BUDGET_MS: u64 = 300;
pub const HFA_PULL_ON_MISS_MAX_CONTEXT_IDS: usize = 1024;
pub const HFA_MAX_FAST_INTENT_MSGS_PER_SEC: u64 = 256;
pub const HFA_MAX_FAST_MICROBLOCK_MSGS_PER_SEC: u64 = 512;
pub const HFA_MAX_REQUEST_FAST_INTENTS_MSGS_PER_SEC: u64 = 128;
pub const HFA_MAX_REQUEST_FAST_INTENT_IDS_PER_SEC: u64 = 4096;

#[derive(Clone, Debug)]
pub struct FastIntentP2pData {
    pub intent_id: Hash,
    pub base_tx: Transaction,
    pub intent_nonce: u64,
    pub client_created_at_ms: u64,
    pub max_fee: u64,
}

#[derive(Clone, Debug)]
pub struct FastMicroblockP2pData {
    pub microblock_time_ms: u64,
    pub intent_ids: Vec<Hash>,
}

#[async_trait]
pub trait HfaP2pBridge: Send + Sync {
    fn hfa_enabled(&self) -> bool;

    fn has_fast_intent(&self, intent_id: Hash) -> bool;

    fn has_fast_lock_conflict_for_tx(&self, tx: &Transaction) -> bool;

    fn get_fast_intents(&self, intent_ids: &[Hash]) -> Vec<FastIntentP2pData>;

    async fn submit_remote_fast_intent(
        &self,
        network_id: &str,
        intent: FastIntentP2pData,
        session: ConsensusProxy,
        mining_manager: MiningManagerProxy,
        is_synced: bool,
        cpu_ratio: f64,
    );

    /// Returns the subset of `intent_ids` that are still unknown locally and should be pulled via RequestFastIntents.
    fn on_remote_fast_microblock(&self, intent_ids: &[Hash], now_ms: u64) -> Vec<Hash>;

    fn record_pull_fail(&self, count: u64);

    /// Returns locally produced microblock notifications that should be relayed to peers.
    fn take_outbound_fast_microblocks(&self) -> Vec<FastMicroblockP2pData>;
}
