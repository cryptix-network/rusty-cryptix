use crate::{
    consensus::test_consensus::TestConsensus,
    model::{
        services::reachability::ReachabilityService,
        stores::{
            atomic_state::{AtomicAssetClass, AtomicBalanceKey, AtomicConsensusState, AtomicLiquidityPoolState, AtomicNonceKey},
            statuses::StatusesStore,
            virtual_state::{VirtualStateStore, VirtualStateStoreReader},
        },
    },
    processes::transaction_validator::transaction_validator_populated::atomic_owner_id_from_script,
};
use cryptix_consensus_core::{
    api::{
        args::{TransactionValidationArgs, TransactionValidationBatchArgs},
        ConsensusApi,
    },
    block::{Block, BlockTemplate, MutableBlock, TemplateBuildMode, TemplateTransactionSelector},
    blockhash,
    blockstatus::BlockStatus,
    coinbase::MinerData,
    config::{params::MAINNET_PARAMS, Config, ConfigBuilder},
    constants::{SOMPI_PER_CRYPTIX, TX_VERSION, UNACCEPTED_DAA_SCORE},
    errors::block::RuleError,
    subnets::{SUBNETWORK_ID_NATIVE, SUBNETWORK_ID_PAYLOAD},
    trusted::TrustedBlock,
    tx::{
        MutableTransaction, ScriptPublicKey, ScriptVec, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput,
        UtxoEntry,
    },
    BlockHashSet,
};
use cryptix_hashes::Hash;
use cryptix_muhash::MuHash;
use std::{collections::VecDeque, sync::Arc, thread::JoinHandle, time::Duration};

#[path = "atomic_stress_crosscheck.rs"]
mod atomic_stress_crosscheck;

struct OnetimeTxSelector {
    txs: Option<Vec<Transaction>>,
    rejected: bool,
}

impl OnetimeTxSelector {
    fn new(txs: Vec<Transaction>) -> Self {
        Self { txs: Some(txs), rejected: false }
    }
}

impl TemplateTransactionSelector for OnetimeTxSelector {
    fn select_transactions(&mut self) -> Vec<Transaction> {
        self.txs.take().unwrap_or_default()
    }

    fn reject_selection(&mut self, _tx_id: cryptix_consensus_core::tx::TransactionId) {
        self.rejected = true;
    }

    fn is_successful(&self) -> bool {
        !self.rejected
    }
}

struct TestContext {
    consensus: TestConsensus,
    join_handles: Vec<JoinHandle<()>>,
    miner_data: MinerData,
    simulated_time: u64,
    current_templates: VecDeque<BlockTemplate>,
    current_tips: BlockHashSet,
}

impl Drop for TestContext {
    fn drop(&mut self) {
        self.consensus.shutdown(std::mem::take(&mut self.join_handles));
    }
}

impl TestContext {
    fn new(consensus: TestConsensus) -> Self {
        let join_handles = consensus.init();
        let genesis_hash = consensus.params().genesis.hash;
        let simulated_time = consensus.params().genesis.timestamp;
        Self {
            consensus,
            join_handles,
            miner_data: new_miner_data(),
            simulated_time,
            current_templates: Default::default(),
            current_tips: BlockHashSet::from_iter([genesis_hash]),
        }
    }

    pub fn build_block_template_row(&mut self, nonces: impl Iterator<Item = usize>) -> &mut Self {
        for nonce in nonces {
            self.simulated_time += self.consensus.params().target_time_per_block;
            self.current_templates.push_back(self.build_block_template(nonce as u64, self.simulated_time));
        }
        self
    }

    pub fn assert_row_parents(&mut self) -> &mut Self {
        for t in self.current_templates.iter() {
            assert_eq!(self.current_tips, BlockHashSet::from_iter(t.block.header.direct_parents().iter().copied()));
        }
        self
    }

    pub async fn validate_and_insert_row(&mut self) -> &mut Self {
        self.current_tips.clear();
        while let Some(t) = self.current_templates.pop_front() {
            self.current_tips.insert(t.block.header.hash);
            self.validate_and_insert_block(t.block.to_immutable()).await;
        }
        self
    }

    pub async fn build_and_insert_disqualified_chain(&mut self, mut parents: Vec<Hash>, len: usize) -> Hash {
        // The chain will be disqualified since build_block_with_parents builds utxo-invalid blocks
        for _ in 0..len {
            self.simulated_time += self.consensus.params().target_time_per_block;
            let b = self.build_block_with_parents(parents, 0, self.simulated_time);
            parents = vec![b.header.hash];
            self.validate_and_insert_block(b.to_immutable()).await;
        }
        parents[0]
    }

    pub fn build_block_template(&self, nonce: u64, timestamp: u64) -> BlockTemplate {
        let mut t = self
            .consensus
            .build_block_template(
                self.miner_data.clone(),
                Box::new(OnetimeTxSelector::new(Default::default())),
                TemplateBuildMode::Standard,
            )
            .unwrap();
        t.block.header.timestamp = timestamp;
        t.block.header.nonce = nonce;
        t.block.header.finalize();
        t
    }

    pub fn build_block_template_with_transactions(&self, txs: Vec<Transaction>, nonce: u64, timestamp: u64) -> BlockTemplate {
        let mut t = self
            .consensus
            .build_block_template(self.miner_data.clone(), Box::new(OnetimeTxSelector::new(txs)), TemplateBuildMode::Standard)
            .unwrap();
        t.block.header.timestamp = timestamp;
        t.block.header.nonce = nonce;
        t.block.header.finalize();
        t
    }

    pub fn build_utxo_valid_block_with_parents_and_transactions(
        &self,
        parents: Vec<Hash>,
        txs: Vec<Transaction>,
        nonce: u64,
        timestamp: u64,
    ) -> MutableBlock {
        let mut b = self.consensus.build_utxo_valid_block_with_parents(blockhash::NONE, parents, self.miner_data.clone(), txs);
        b.header.timestamp = timestamp;
        b.header.nonce = nonce;
        b.header.finalize();
        b
    }

    pub fn build_block_with_parents(&self, parents: Vec<Hash>, nonce: u64, timestamp: u64) -> MutableBlock {
        let mut b = self.consensus.build_block_with_parents_and_transactions(blockhash::NONE, parents, Default::default());
        b.header.timestamp = timestamp;
        b.header.nonce = nonce;
        b.header.finalize(); // This overrides the NONE hash we passed earlier with the actual hash
        b
    }

    pub async fn validate_and_insert_block(&mut self, block: Block) -> &mut Self {
        let status = self.consensus.validate_and_insert_block(block).virtual_state_task.await.unwrap();
        assert!(status.has_block_body());
        self
    }

    pub async fn validate_and_insert_utxo_valid_block(&mut self, block: Block) -> &mut Self {
        let hash = block.hash();
        let status = self.consensus.validate_and_insert_block(block).virtual_state_task.await.unwrap();
        assert_eq!(status, BlockStatus::StatusUTXOValid, "block {hash} must be UTXO/Atomic valid");
        self
    }

    pub fn assert_tips(&mut self) -> &mut Self {
        assert_eq!(BlockHashSet::from_iter(self.consensus.get_tips().into_iter()), self.current_tips);
        self
    }

    pub fn assert_tips_num(&mut self, expected_num: usize) -> &mut Self {
        assert_eq!(BlockHashSet::from_iter(self.consensus.get_tips().into_iter()).len(), expected_num);
        self
    }

    pub fn assert_virtual_parents_subset(&mut self) -> &mut Self {
        assert!(self.consensus.get_virtual_parents().is_subset(&self.current_tips));
        self
    }

    pub fn assert_valid_utxo_tip(&mut self) -> &mut Self {
        // Assert that at least one body tip was resolved with valid UTXO
        assert!(self.consensus.body_tips().iter().copied().any(|h| self.consensus.block_status(h) == BlockStatus::StatusUTXOValid));
        self
    }
}

#[tokio::test]
async fn template_mining_sanity_test() {
    let config = ConfigBuilder::new(MAINNET_PARAMS).skip_proof_of_work().build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let rounds = 10;
    let width = 3;
    for _ in 0..rounds {
        ctx.build_block_template_row(0..width)
            .assert_row_parents()
            .validate_and_insert_row()
            .await
            .assert_tips()
            .assert_virtual_parents_subset()
            .assert_valid_utxo_tip();
    }
}

#[tokio::test]
async fn antichain_merge_test() {
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
        })
        .build();

    let mut ctx = TestContext::new(TestConsensus::new(&config));

    // Build a large 32-wide antichain
    ctx.build_block_template_row(0..32)
        .validate_and_insert_row()
        .await
        .assert_tips()
        .assert_virtual_parents_subset()
        .assert_valid_utxo_tip();

    // Mine a long enough chain s.t. the antichain is fully merged
    for _ in 0..32 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await.assert_valid_utxo_tip();
    }
    ctx.assert_tips_num(1);
}

#[tokio::test]
async fn basic_utxo_disqualified_test() {
    cryptix_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
        })
        .build();

    let mut ctx = TestContext::new(TestConsensus::new(&config));

    // Mine a valid chain
    for _ in 0..10 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await.assert_valid_utxo_tip();
    }

    // Get current sink
    let sink = ctx.consensus.get_sink();

    // Mine a longer disqualified chain
    let disqualified_tip = ctx.build_and_insert_disqualified_chain(vec![config.genesis.hash], 20).await;

    assert_ne!(sink, disqualified_tip);
    assert_eq!(sink, ctx.consensus.get_sink());
    assert_eq!(BlockHashSet::from_iter([sink]), BlockHashSet::from_iter(ctx.consensus.get_tips().into_iter()));
    assert!(!ctx.consensus.get_virtual_parents().contains(&disqualified_tip));
}

#[tokio::test]
async fn atomic_disqualified_branch_does_not_poison_virtual_progress() {
    let (mut ctx, fixture) = setup_dual_owner_liquidity_pool().await;
    let valid_sink_before = ctx.consensus.get_sink();
    assert_eq!(ctx.consensus.get_block_status(valid_sink_before), Some(BlockStatus::StatusUTXOValid));

    let disqualified_tip = ctx.build_and_insert_disqualified_chain(vec![fixture.create_block_hash], 4).await;
    assert_eq!(ctx.consensus.get_block_status(disqualified_tip), Some(BlockStatus::StatusDisqualifiedFromChain));
    assert_eq!(ctx.consensus.get_sink(), valid_sink_before);
    assert!(!ctx.consensus.get_tips().contains(&disqualified_tip));
    assert!(!ctx.consensus.get_virtual_parents().contains(&disqualified_tip));

    let mut last_valid_hash = valid_sink_before;
    for nonce in 900..905 {
        ctx.simulated_time += ctx.consensus.params().target_time_per_block;
        let valid_extension = ctx.build_block_template(nonce, ctx.simulated_time);
        last_valid_hash = valid_extension.block.header.hash;
        ctx.validate_and_insert_block(valid_extension.block.to_immutable()).await;
        assert_eq!(ctx.consensus.get_block_status(last_valid_hash), Some(BlockStatus::StatusUTXOValid));
        assert!(!ctx.consensus.get_virtual_parents().contains(&disqualified_tip));
    }

    assert!(ctx.consensus.reachability_service().is_chain_ancestor_of(valid_sink_before, last_valid_hash));
    assert_eq!(ctx.consensus.get_sink(), last_valid_hash);
    let atomic = ctx.consensus.virtual_atomic_state();
    assert!(atomic.assets.contains_key(&fixture.asset_id));
    let asset = atomic.assets.get(&fixture.asset_id).expect("liquidity asset should remain live");
    assert_eq!(asset.liquidity.as_ref().expect("pool should remain live").pool_nonce, fixture.pool.pool_nonce);
}

#[tokio::test]
async fn disqualified_only_tip_restores_last_valid_parent() {
    cryptix_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
        })
        .build();

    let mut ctx = TestContext::new(TestConsensus::new(&config));
    for _ in 0..6 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await.assert_valid_utxo_tip();
    }

    let valid_sink = ctx.consensus.get_sink();
    assert_eq!(BlockHashSet::from_iter([valid_sink]), BlockHashSet::from_iter(ctx.consensus.get_tips().into_iter()));

    let disqualified_tip = ctx.build_and_insert_disqualified_chain(vec![valid_sink], 1).await;
    assert_eq!(ctx.consensus.get_block_status(disqualified_tip), Some(BlockStatus::StatusDisqualifiedFromChain));
    assert_eq!(ctx.consensus.get_sink(), valid_sink);
    assert_eq!(BlockHashSet::from_iter([valid_sink]), BlockHashSet::from_iter(ctx.consensus.get_tips().into_iter()));
    assert!(!ctx.consensus.get_virtual_parents().contains(&disqualified_tip));

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let valid_extension = ctx.build_block_template(910, ctx.simulated_time);
    let valid_extension_hash = valid_extension.block.header.hash;
    ctx.validate_and_insert_block(valid_extension.block.to_immutable()).await;
    assert_eq!(ctx.consensus.get_block_status(valid_extension_hash), Some(BlockStatus::StatusUTXOValid));
    assert_eq!(ctx.consensus.get_sink(), valid_extension_hash);
}

#[tokio::test]
async fn disqualified_sibling_does_not_reapply_selected_parent_atomic_delta() {
    cryptix_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.coinbase_maturity = 0;
            p.payload_hf_activation_daa_score = 0;
        })
        .build();

    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let owner_script = cryptix_txscript::pay_to_script_hash_script(&p2sh_redeem_script());
    ctx.miner_data = MinerData::new(owner_script.clone(), vec![]);

    for _ in 0..3 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await.assert_valid_utxo_tip();
    }

    let (funding_outpoint, funding_entry) = find_virtual_utxo_by_script(&ctx, &owner_script);
    let tx_fee = 10_000u64;
    let anchor_tx = Transaction::new(
        TX_VERSION,
        vec![TransactionInput::new(funding_outpoint, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(funding_entry.amount - tx_fee, owner_script.clone())],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let anchor_template = ctx.build_block_template_with_transactions(vec![anchor_tx], 700, ctx.simulated_time);
    let valid_sink = anchor_template.block.header.hash;
    ctx.validate_and_insert_utxo_valid_block(anchor_template.block.to_immutable()).await;
    assert_eq!(ctx.consensus.get_sink(), valid_sink);
    let expected_atomic_hash = ctx.consensus.virtual_atomic_state().canonical_hash();

    for nonce in 701..704 {
        ctx.simulated_time += ctx.consensus.params().target_time_per_block;
        let invalid_child = ctx.build_block_with_parents(vec![valid_sink], nonce, ctx.simulated_time);
        let invalid_hash = invalid_child.header.hash;
        let status = ctx.consensus.validate_and_insert_block(invalid_child.to_immutable()).virtual_state_task.await.unwrap();
        assert_eq!(status, BlockStatus::StatusDisqualifiedFromChain);
        assert_eq!(ctx.consensus.get_block_status(invalid_hash), Some(BlockStatus::StatusDisqualifiedFromChain));
        assert_eq!(ctx.consensus.get_sink(), valid_sink);
        assert_eq!(
            ctx.consensus.virtual_atomic_state().canonical_hash(),
            expected_atomic_hash,
            "disqualified sibling {invalid_hash} must not reapply the selected-parent Atomic delta"
        );
    }

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let valid_extension = ctx.build_block_template(704, ctx.simulated_time);
    let valid_extension_hash = valid_extension.block.header.hash;
    ctx.validate_and_insert_utxo_valid_block(valid_extension.block.to_immutable()).await;
    assert_eq!(ctx.consensus.get_sink(), valid_extension_hash);
}

#[tokio::test]
async fn disqualified_cached_chain_block_does_not_advance_virtual_state() {
    cryptix_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.coinbase_maturity = 0;
            p.payload_hf_activation_daa_score = 0;
        })
        .build();

    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let owner_script = cryptix_txscript::pay_to_script_hash_script(&p2sh_redeem_script());
    ctx.miner_data = MinerData::new(owner_script.clone(), vec![]);

    for _ in 0..3 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await.assert_valid_utxo_tip();
    }

    let safe_parent = ctx.consensus.get_sink();
    let (funding_outpoint, funding_entry) = find_virtual_utxo_by_script(&ctx, &owner_script);
    let tx_fee = 10_000u64;
    let anchor_tx = Transaction::new(
        TX_VERSION,
        vec![TransactionInput::new(funding_outpoint, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(funding_entry.amount - tx_fee, owner_script.clone())],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let cached_template = ctx.build_block_template_with_transactions(vec![anchor_tx], 800, ctx.simulated_time);
    let cached_hash = cached_template.block.header.hash;
    ctx.validate_and_insert_utxo_valid_block(cached_template.block.to_immutable()).await;
    assert_eq!(ctx.consensus.get_sink(), cached_hash);

    ctx.consensus.virtual_processor().statuses_store.write().set(cached_hash, BlockStatus::StatusDisqualifiedFromChain).unwrap();
    assert_eq!(ctx.consensus.get_block_status(cached_hash), Some(BlockStatus::StatusDisqualifiedFromChain));

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let sibling = ctx.build_utxo_valid_block_with_parents_and_transactions(vec![safe_parent], vec![], 801, ctx.simulated_time);
    let sibling_hash = sibling.header.hash;
    ctx.validate_and_insert_utxo_valid_block(sibling.to_immutable()).await;
    assert_eq!(ctx.consensus.get_sink(), sibling_hash);
    let expected_atomic_hash = ctx.consensus.virtual_atomic_state().canonical_hash();

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let child_of_disqualified = ctx.build_block_with_parents(vec![cached_hash], 802, ctx.simulated_time);
    let child_hash = child_of_disqualified.header.hash;
    let status = ctx.consensus.validate_and_insert_block(child_of_disqualified.to_immutable()).virtual_state_task.await.unwrap();

    assert_eq!(status, BlockStatus::StatusDisqualifiedFromChain);
    assert_eq!(ctx.consensus.get_block_status(child_hash), Some(BlockStatus::StatusDisqualifiedFromChain));
    assert_eq!(ctx.consensus.get_sink(), sibling_hash);
    assert_eq!(
        ctx.consensus.virtual_atomic_state().canonical_hash(),
        expected_atomic_hash,
        "a disqualified selected-chain block with cached UTXO/Atomic data must not advance virtual state"
    );
}

#[tokio::test]
async fn missing_virtual_atomic_delta_is_recovered_before_revalidating_candidates() {
    cryptix_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.coinbase_maturity = 0;
            p.payload_hf_activation_daa_score = 0;
        })
        .build();

    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let owner_script = cryptix_txscript::pay_to_script_hash_script(&p2sh_redeem_script());
    ctx.miner_data = MinerData::new(owner_script.clone(), vec![]);

    for _ in 0..3 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await.assert_valid_utxo_tip();
    }

    let (funding_outpoint, funding_entry) = find_virtual_utxo_by_script(&ctx, &owner_script);
    let tx_fee = 10_000u64;
    let native_anchor_tx = Transaction::new(
        TX_VERSION,
        vec![TransactionInput::new(funding_outpoint, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(funding_entry.amount - tx_fee, owner_script.clone())],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );
    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let anchor_template = ctx.build_block_template_with_transactions(vec![native_anchor_tx], 7_100, ctx.simulated_time);
    let valid_sink = anchor_template.block.header.hash;
    ctx.validate_and_insert_utxo_valid_block(anchor_template.block.to_immutable()).await;
    assert_eq!(ctx.consensus.get_sink(), valid_sink);

    {
        let virtual_stores = ctx.consensus.virtual_stores();
        let mut write = virtual_stores.write();
        let mut corrupted = write.state.get().expect("virtual state").as_ref().clone();
        assert!(!corrupted.atomic_diff.is_empty(), "test setup must have a non-empty virtual Atomic delta");
        corrupted.atomic_diff = Default::default();
        write.state.set(Arc::new(corrupted)).expect("corrupt virtual Atomic delta for regression test");
    }

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let mined_template = ctx.build_block_template(7_101, ctx.simulated_time);
    let mined_hash = mined_template.block.header.hash;
    let mined_status = ctx.consensus.validate_and_insert_block(mined_template.block.to_immutable()).virtual_state_task.await.unwrap();
    assert_eq!(
        mined_status,
        BlockStatus::StatusUTXOValid,
        "template {mined_hash} built from a virtual state with a missing Atomic diff must still validate"
    );
    assert_eq!(ctx.consensus.get_sink(), mined_hash);
    let valid_sink = mined_hash;
    let expected_atomic_hash = ctx.consensus.virtual_atomic_state().canonical_hash();

    for nonce in 7_101..7_104 {
        ctx.simulated_time += ctx.consensus.params().target_time_per_block;
        let invalid_child = ctx.build_block_with_parents(vec![valid_sink], nonce, ctx.simulated_time);
        let invalid_hash = invalid_child.header.hash;
        let status = ctx.consensus.validate_and_insert_block(invalid_child.to_immutable()).virtual_state_task.await.unwrap();
        assert_eq!(status, BlockStatus::StatusDisqualifiedFromChain);
        assert_eq!(ctx.consensus.get_block_status(invalid_hash), Some(BlockStatus::StatusDisqualifiedFromChain));
        assert_eq!(ctx.consensus.get_sink(), valid_sink);
        assert_eq!(
            ctx.consensus.virtual_atomic_state().canonical_hash(),
            expected_atomic_hash,
            "missing virtual Atomic delta must be repaired instead of reapplying the selected parent"
        );
    }

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let valid_extension = ctx.build_block_template(7_104, ctx.simulated_time);
    let valid_extension_hash = valid_extension.block.header.hash;
    ctx.validate_and_insert_utxo_valid_block(valid_extension.block.to_immutable()).await;
    assert_eq!(ctx.consensus.get_sink(), valid_extension_hash);
}

#[tokio::test]
async fn block_template_refuses_disqualified_virtual_selected_parent() {
    cryptix_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS).skip_proof_of_work().build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));
    ctx.build_block_template_row(0..3).validate_and_insert_row().await.assert_valid_utxo_tip();

    let selected_parent = ctx.consensus.get_sink();
    assert_eq!(ctx.consensus.get_block_status(selected_parent), Some(BlockStatus::StatusUTXOValid));
    ctx.consensus.virtual_processor().statuses_store.write().set(selected_parent, BlockStatus::StatusDisqualifiedFromChain).unwrap();

    let err = ctx
        .consensus
        .build_block_template(
            ctx.miner_data.clone(),
            Box::new(OnetimeTxSelector::new(Default::default())),
            TemplateBuildMode::Standard,
        )
        .unwrap_err();

    assert!(matches!(err, crate::errors::RuleError::KnownInvalid));
}

#[tokio::test]
async fn double_search_disqualified_test() {
    // TODO: add non-coinbase transactions and concurrency in order to complicate the test

    cryptix_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
            p.min_difficulty_window_len = p.legacy_difficulty_window_size;
        })
        .build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));

    // Mine 3 valid blocks over genesis
    ctx.build_block_template_row(0..3)
        .validate_and_insert_row()
        .await
        .assert_tips()
        .assert_virtual_parents_subset()
        .assert_valid_utxo_tip();

    // Mark the one expected to remain on virtual chain
    let original_sink = ctx.consensus.get_sink();

    // Find the roots to be used for the disqualified chains
    let mut virtual_parents = ctx.consensus.get_virtual_parents();
    assert!(virtual_parents.remove(&original_sink));
    let mut iter = virtual_parents.into_iter();
    let root_1 = iter.next().unwrap();
    let root_2 = iter.next().unwrap();
    assert_eq!(iter.next(), None);

    // Mine a valid chain
    for _ in 0..10 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await.assert_valid_utxo_tip();
    }

    // Get current sink
    let sink = ctx.consensus.get_sink();

    assert!(ctx.consensus.reachability_service().is_chain_ancestor_of(original_sink, sink));

    // Mine a long disqualified chain
    let disqualified_tip_1 = ctx.build_and_insert_disqualified_chain(vec![root_1], 30).await;

    // And another shorter disqualified chain
    let disqualified_tip_2 = ctx.build_and_insert_disqualified_chain(vec![root_2], 20).await;

    assert_eq!(ctx.consensus.get_block_status(root_1), Some(BlockStatus::StatusUTXOValid));
    assert_eq!(ctx.consensus.get_block_status(root_2), Some(BlockStatus::StatusUTXOValid));

    assert_ne!(sink, disqualified_tip_1);
    assert_ne!(sink, disqualified_tip_2);
    assert_eq!(sink, ctx.consensus.get_sink());
    assert_eq!(BlockHashSet::from_iter([sink]), BlockHashSet::from_iter(ctx.consensus.get_tips().into_iter()));
    assert!(!ctx.consensus.get_virtual_parents().contains(&disqualified_tip_1));
    assert!(!ctx.consensus.get_virtual_parents().contains(&disqualified_tip_2));

    // Mine a long enough valid chain s.t. both disqualified chains are fully merged
    for _ in 0..30 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await.assert_valid_utxo_tip();
    }
    ctx.assert_tips_num(1);
}

fn p2sh_redeem_script() -> Vec<u8> {
    vec![0x51]
}

fn second_p2sh_redeem_script() -> Vec<u8> {
    vec![0x51, 0x75, 0x51]
}

fn p2sh_signature_script_for(redeem_script: &[u8]) -> Vec<u8> {
    cryptix_txscript::pay_to_script_hash_signature_script(redeem_script.to_vec(), vec![]).unwrap()
}

fn p2sh_signature_script() -> Vec<u8> {
    p2sh_signature_script_for(&p2sh_redeem_script())
}

fn cat_header(op: u8, auth_input_index: u16, nonce: u64) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"CAT");
    payload.push(1);
    payload.push(op);
    payload.push(0);
    payload.extend_from_slice(&auth_input_index.to_le_bytes());
    payload.extend_from_slice(&nonce.to_le_bytes());
    payload
}

fn payload_create_liquidity(
    auth_input_index: u16,
    nonce: u64,
    max_supply: u128,
    seed_reserve_sompi: u64,
    fee_bps: u16,
    recipient_script_payload: &[u8],
    launch_buy_sompi: u64,
    launch_buy_min_token_out: u128,
) -> Vec<u8> {
    let mut payload = cat_header(5, auth_input_index, nonce);
    payload.push(1);
    payload.push(1);
    payload.push(0);
    payload.extend_from_slice(&max_supply.to_le_bytes());
    payload.push(4);
    payload.push(3);
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(b"Pool");
    payload.extend_from_slice(b"POL");
    payload.extend_from_slice(&seed_reserve_sompi.to_le_bytes());
    payload.extend_from_slice(&fee_bps.to_le_bytes());
    payload.push(1);
    payload.push(8);
    payload.extend_from_slice(recipient_script_payload);
    payload.extend_from_slice(&launch_buy_sompi.to_le_bytes());
    payload.extend_from_slice(&launch_buy_min_token_out.to_le_bytes());
    payload
}

fn payload_create_asset_with_mint(
    auth_input_index: u16,
    nonce: u64,
    mint_authority_owner_id: [u8; 32],
    name: &[u8],
    symbol: &[u8],
    initial_mint_amount: u128,
    initial_mint_to_owner_id: [u8; 32],
) -> Vec<u8> {
    let mut payload = cat_header(4, auth_input_index, nonce);
    payload.push(1);
    payload.push(8);
    payload.push(0);
    payload.extend_from_slice(&0u128.to_le_bytes());
    payload.extend_from_slice(&mint_authority_owner_id);
    payload.push(name.len() as u8);
    payload.push(symbol.len() as u8);
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(name);
    payload.extend_from_slice(symbol);
    payload.extend_from_slice(&initial_mint_amount.to_le_bytes());
    payload.extend_from_slice(&initial_mint_to_owner_id);
    payload
}

fn payload_create_asset(auth_input_index: u16, nonce: u64, mint_authority_owner_id: [u8; 32], name: &[u8], symbol: &[u8]) -> Vec<u8> {
    let mut payload = cat_header(0, auth_input_index, nonce);
    payload.push(1);
    payload.push(8);
    payload.push(0);
    payload.extend_from_slice(&0u128.to_le_bytes());
    payload.extend_from_slice(&mint_authority_owner_id);
    payload.push(name.len() as u8);
    payload.push(symbol.len() as u8);
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(name);
    payload.extend_from_slice(symbol);
    payload
}

fn payload_mint(auth_input_index: u16, nonce: u64, asset_id: [u8; 32], to_owner_id: [u8; 32], amount: u128) -> Vec<u8> {
    let mut payload = cat_header(2, auth_input_index, nonce);
    payload.extend_from_slice(&asset_id);
    payload.extend_from_slice(&to_owner_id);
    payload.extend_from_slice(&amount.to_le_bytes());
    payload
}

fn payload_burn(auth_input_index: u16, nonce: u64, asset_id: [u8; 32], amount: u128) -> Vec<u8> {
    let mut payload = cat_header(3, auth_input_index, nonce);
    payload.extend_from_slice(&asset_id);
    payload.extend_from_slice(&amount.to_le_bytes());
    payload
}

fn payload_transfer(auth_input_index: u16, nonce: u64, asset_id: [u8; 32], to_owner_id: [u8; 32], amount: u128) -> Vec<u8> {
    let mut payload = cat_header(1, auth_input_index, nonce);
    payload.extend_from_slice(&asset_id);
    payload.extend_from_slice(&to_owner_id);
    payload.extend_from_slice(&amount.to_le_bytes());
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
    let mut payload = cat_header(6, auth_input_index, nonce);
    payload.extend_from_slice(&asset_id);
    payload.extend_from_slice(&expected_pool_nonce.to_le_bytes());
    payload.extend_from_slice(&cpay_in_sompi.to_le_bytes());
    payload.extend_from_slice(&min_token_out.to_le_bytes());
    payload
}

fn payload_sell_liquidity(
    auth_input_index: u16,
    nonce: u64,
    asset_id: [u8; 32],
    expected_pool_nonce: u64,
    token_in: u128,
    min_cpay_out_sompi: u64,
    cpay_receive_output_index: u16,
) -> Vec<u8> {
    let mut payload = cat_header(7, auth_input_index, nonce);
    payload.extend_from_slice(&asset_id);
    payload.extend_from_slice(&expected_pool_nonce.to_le_bytes());
    payload.extend_from_slice(&token_in.to_le_bytes());
    payload.extend_from_slice(&min_cpay_out_sompi.to_le_bytes());
    payload.extend_from_slice(&cpay_receive_output_index.to_le_bytes());
    payload
}

fn payload_claim_liquidity(
    auth_input_index: u16,
    nonce: u64,
    asset_id: [u8; 32],
    expected_pool_nonce: u64,
    recipient_index: u8,
    claim_amount_sompi: u64,
    claim_receive_output_index: u16,
) -> Vec<u8> {
    let mut payload = cat_header(8, auth_input_index, nonce);
    payload.extend_from_slice(&asset_id);
    payload.extend_from_slice(&expected_pool_nonce.to_le_bytes());
    payload.push(recipient_index);
    payload.extend_from_slice(&claim_amount_sompi.to_le_bytes());
    payload.extend_from_slice(&claim_receive_output_index.to_le_bytes());
    payload
}

fn liquidity_vault_script() -> ScriptPublicKey {
    ScriptPublicKey::new(0, ScriptVec::from_slice(&[0x04, b'C', b'L', b'V', b'1', 0x75, 0x51]))
}

fn payload_tx(inputs: Vec<TransactionInput>, outputs: Vec<TransactionOutput>, payload: Vec<u8>) -> Transaction {
    let mut tx = Transaction::new(TX_VERSION, inputs, outputs, 0, SUBNETWORK_ID_PAYLOAD, 0, payload);
    tx.finalize();
    tx
}

fn native_tx(inputs: Vec<TransactionInput>, outputs: Vec<TransactionOutput>) -> Transaction {
    let mut tx = Transaction::new(TX_VERSION, inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    tx.finalize();
    tx
}

fn find_virtual_utxo_by_script(
    ctx: &TestContext,
    script_public_key: &ScriptPublicKey,
) -> (TransactionOutpoint, cryptix_consensus_core::tx::UtxoEntry) {
    let mut from_outpoint = None;
    let mut skip_first = false;
    let mut seen = 0usize;
    let mut sample_scripts = Vec::new();
    loop {
        let chunk = ctx.consensus.get_virtual_utxos(from_outpoint, 1_000, skip_first);
        if chunk.is_empty() {
            panic!("script-owned virtual UTXO not found; scanned {seen} UTXOs; sample script lengths: {sample_scripts:?}");
        }
        if let Some(found) = chunk.iter().find(|(_, entry)| entry.script_public_key == *script_public_key) {
            return found.clone();
        }
        seen += chunk.len();
        for (_, entry) in chunk.iter().take(3) {
            if sample_scripts.len() < 8 {
                sample_scripts.push((entry.amount, entry.script_public_key.version(), entry.script_public_key.script().len()));
            }
        }
        from_outpoint = chunk.last().map(|(outpoint, _)| *outpoint);
        skip_first = true;
    }
}

fn find_virtual_utxos_by_script(
    ctx: &TestContext,
    script_public_key: &ScriptPublicKey,
    count: usize,
) -> Vec<(TransactionOutpoint, cryptix_consensus_core::tx::UtxoEntry)> {
    let mut out = Vec::new();
    let mut from_outpoint = None;
    let mut skip_first = false;
    let mut seen = 0usize;
    loop {
        let chunk = ctx.consensus.get_virtual_utxos(from_outpoint, 1_000, skip_first);
        if chunk.is_empty() {
            panic!("script-owned virtual UTXOs not found; needed {count}, found {}, scanned {seen}", out.len());
        }
        for (outpoint, entry) in chunk.iter() {
            if entry.script_public_key == *script_public_key {
                out.push((*outpoint, entry.clone()));
                if out.len() == count {
                    return out;
                }
            }
        }
        seen += chunk.len();
        from_outpoint = chunk.last().map(|(outpoint, _)| *outpoint);
        skip_first = true;
    }
}

#[test]
fn pre_hf_atomic_state_reconstruction_counts_owner_utxos() {
    let owner_script = cryptix_txscript::pay_to_script_hash_script(&p2sh_redeem_script());
    let second_owner_script = cryptix_txscript::pay_to_script_hash_script(&second_p2sh_redeem_script());
    let owner_id = atomic_owner_id_from_script(&owner_script).expect("owner id should derive from P2SH");
    let second_owner_id = atomic_owner_id_from_script(&second_owner_script).expect("second owner id should derive from P2SH");
    let non_owner_script = ScriptPublicKey::new(0, ScriptVec::from_slice(&[0x51]));

    let utxos: Vec<Result<(TransactionOutpoint, Arc<UtxoEntry>), String>> = vec![
        Ok((TransactionOutpoint::new(Hash::from_u64_word(1), 0), Arc::new(UtxoEntry::new(10, owner_script.clone(), 1, false)))),
        Ok((TransactionOutpoint::new(Hash::from_u64_word(2), 0), Arc::new(UtxoEntry::new(20, owner_script.clone(), 2, false)))),
        Ok((TransactionOutpoint::new(Hash::from_u64_word(3), 0), Arc::new(UtxoEntry::new(30, second_owner_script, 3, false)))),
        Ok((TransactionOutpoint::new(Hash::from_u64_word(4), 0), Arc::new(UtxoEntry::new(40, non_owner_script, 4, false)))),
        Ok((TransactionOutpoint::new(Hash::from_u64_word(5), 0), Arc::new(UtxoEntry::new(50, owner_script, 5, true)))),
    ];

    let state = super::processor::VirtualStateProcessor::atomic_anchor_state_from_utxo_iterator(utxos, "test UTXO set")
        .expect("UTXO-derived atomic state should be valid");

    assert_eq!(state.anchor_counts.get(&owner_id).copied(), Some(2));
    assert_eq!(state.anchor_counts.get(&second_owner_id).copied(), Some(1));
    assert_eq!(state.anchor_counts.len(), 2);
    assert!(state.next_nonces.is_empty());
    assert!(state.assets.is_empty());
    assert!(state.balances.is_empty());
}

fn fee(amount: u64, fee_bps: u16) -> u64 {
    (u128::from(amount) * u128::from(fee_bps) / 10_000) as u64
}

fn ceil_div(n: u128, d: u128) -> u128 {
    (n + d - 1) / d
}

fn quote_buy(
    real_token_reserves: u128,
    virtual_cpay_reserves_sompi: u64,
    virtual_token_reserves: u128,
    cpay_in_sompi: u64,
    fee_bps: u16,
) -> (u64, u128) {
    let trade_fee = fee(cpay_in_sompi, fee_bps);
    let net = cpay_in_sompi - trade_fee;
    let x_before = u128::from(virtual_cpay_reserves_sompi);
    let x_after = x_before + u128::from(net);
    let y_after = ceil_div(x_before * virtual_token_reserves, x_after);
    let token_out = virtual_token_reserves - y_after;
    assert!(token_out < real_token_reserves);
    (trade_fee, token_out)
}

fn min_gross_for_net_input(net_in: u64, fee_bps: u16) -> u64 {
    if fee_bps == 0 {
        return net_in;
    }
    let denominator = 10_000u128 - u128::from(fee_bps);
    let gross = ((u128::from(net_in) - 1) * 10_000u128) / denominator + 1;
    u64::try_from(gross).unwrap()
}

fn min_gross_for_token_out(
    real_token_reserves: u128,
    virtual_cpay_reserves_sompi: u64,
    virtual_token_reserves: u128,
    token_out: u128,
    fee_bps: u16,
) -> u64 {
    assert!(token_out > 0);
    assert!(token_out < real_token_reserves);
    let y_after = virtual_token_reserves - token_out;
    let x_before = u128::from(virtual_cpay_reserves_sompi);
    let x_after = ceil_div(x_before * virtual_token_reserves, y_after);
    min_gross_for_net_input(u64::try_from(x_after - x_before).unwrap(), fee_bps)
}

fn canonical_buy_from_budget(
    real_token_reserves: u128,
    virtual_cpay_reserves_sompi: u64,
    virtual_token_reserves: u128,
    budget_in_sompi: u64,
    fee_bps: u16,
) -> (u64, u128) {
    let (_, token_out) = quote_buy(real_token_reserves, virtual_cpay_reserves_sompi, virtual_token_reserves, budget_in_sompi, fee_bps);
    let canonical_in =
        min_gross_for_token_out(real_token_reserves, virtual_cpay_reserves_sompi, virtual_token_reserves, token_out, fee_bps);
    (canonical_in, token_out)
}

const INITIAL_LIQUIDITY_VIRTUAL_CPAY_RESERVES_SOMPI: u64 = 250_000_000_000_000;

fn initial_liquidity_virtual_token_reserves(max_supply: u128) -> u128 {
    max_supply * 6 / 5
}

fn quote_sell(virtual_cpay_reserves_sompi: u64, virtual_token_reserves: u128, token_in: u128, fee_bps: u16) -> (u64, u64) {
    let y_after = virtual_token_reserves + token_in;
    let x_before = u128::from(virtual_cpay_reserves_sompi);
    let numerator = x_before * virtual_token_reserves;
    let x_after = numerator / y_after + u128::from(numerator % y_after != 0);
    let gross = u64::try_from(x_before - x_after).unwrap();
    let trade_fee = fee(gross, fee_bps);
    (trade_fee, gross - trade_fee)
}

struct DualOwnerLiquidityFixture {
    owner_script: ScriptPublicKey,
    owner_id: [u8; 32],
    second_owner_script: ScriptPublicKey,
    second_owner_id: [u8; 32],
    asset_id: [u8; 32],
    create_block_hash: Hash,
    pool: AtomicLiquidityPoolState,
    owner_anchor: TransactionOutpoint,
    owner_anchor_value: u64,
    second_owner_anchor: TransactionOutpoint,
    second_owner_anchor_value: u64,
    launch_token_out: u128,
    tx_fee: u64,
}

fn liquidity_test_context() -> TestContext {
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.coinbase_maturity = 0;
            p.payload_hf_activation_daa_score = 0;
        })
        .build();
    TestContext::new(TestConsensus::new(&config))
}

#[tokio::test]
async fn native_block_template_rejects_same_utxo_double_spend_before_state() {
    let mut ctx = liquidity_test_context();
    let owner_script = cryptix_txscript::pay_to_script_hash_script(&p2sh_redeem_script());
    let second_owner_script = cryptix_txscript::pay_to_script_hash_script(&second_p2sh_redeem_script());
    ctx.miner_data = MinerData::new(owner_script.clone(), vec![]);

    for _ in 0..4 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await;
    }
    let (funding_outpoint, funding_entry) = find_virtual_utxo_by_script(&ctx, &owner_script);
    let tx_fee = 10_000u64;
    let first = native_tx(
        vec![TransactionInput::new(funding_outpoint, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(funding_entry.amount - tx_fee, owner_script.clone())],
    );
    let second = native_tx(
        vec![TransactionInput::new(funding_outpoint, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(funding_entry.amount - tx_fee, second_owner_script)],
    );

    let result = ctx.consensus.build_block_template(
        ctx.miner_data.clone(),
        Box::new(OnetimeTxSelector::new(vec![first, second])),
        TemplateBuildMode::Standard,
    );

    assert!(result.is_err(), "same-UTXO native double spend must not be mined into a template");
    assert!(format!("{result:?}").contains("MissingTxOutpoints"), "template rejection should report the UTXO conflict: {result:?}");
}

#[tokio::test]
async fn native_parallel_same_utxo_blocks_accept_spend_once_in_virtual_mergeset() {
    let mut ctx = liquidity_test_context();
    let owner_script = cryptix_txscript::pay_to_script_hash_script(&p2sh_redeem_script());
    let second_owner_script = cryptix_txscript::pay_to_script_hash_script(&second_p2sh_redeem_script());
    ctx.miner_data = MinerData::new(owner_script.clone(), vec![]);

    for _ in 0..4 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await;
    }
    let fork_parent = ctx.consensus.get_sink();
    let (funding_outpoint, funding_entry) = find_virtual_utxo_by_script(&ctx, &owner_script);
    let tx_fee = 10_000u64;
    let first = native_tx(
        vec![TransactionInput::new(funding_outpoint, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(funding_entry.amount - tx_fee, owner_script)],
    );
    let second = native_tx(
        vec![TransactionInput::new(funding_outpoint, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(funding_entry.amount - tx_fee, second_owner_script)],
    );
    let first_txid = first.id();
    let second_txid = second.id();

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let first_block =
        ctx.build_utxo_valid_block_with_parents_and_transactions(vec![fork_parent], vec![first], 7_000, ctx.simulated_time);
    let first_block_hash = first_block.header.hash;
    ctx.validate_and_insert_block(first_block.to_immutable()).await;

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let second_block =
        ctx.build_utxo_valid_block_with_parents_and_transactions(vec![fork_parent], vec![second], 7_001, ctx.simulated_time);
    let second_block_hash = second_block.header.hash;
    ctx.validate_and_insert_block(second_block.to_immutable()).await;

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let merge_block = ctx.build_utxo_valid_block_with_parents_and_transactions(
        vec![first_block_hash, second_block_hash],
        vec![],
        7_002,
        ctx.simulated_time,
    );
    let merge_hash = merge_block.header.hash;
    ctx.validate_and_insert_utxo_valid_block(merge_block.to_immutable()).await;

    let acceptance_data = ctx.consensus.get_block_acceptance_data(merge_hash).expect("merge acceptance data should exist");
    let accepted_txids: Vec<_> = acceptance_data
        .iter()
        .flat_map(|block_acceptance| block_acceptance.accepted_transactions.iter())
        .map(|tx| tx.transaction_id)
        .collect();
    let accepted_conflicts = accepted_txids.iter().filter(|txid| **txid == first_txid || **txid == second_txid).count();
    assert_eq!(accepted_conflicts, 1, "only one parallel spend of the same UTXO may be accepted: {accepted_txids:?}");

    let virtual_utxos = ctx.consensus.get_virtual_utxos(None, 10_000, false);
    let original_still_unspent = virtual_utxos.iter().any(|(outpoint, _)| *outpoint == funding_outpoint);
    let first_output_exists = virtual_utxos.iter().any(|(outpoint, _)| *outpoint == TransactionOutpoint::new(first_txid, 0));
    let second_output_exists = virtual_utxos.iter().any(|(outpoint, _)| *outpoint == TransactionOutpoint::new(second_txid, 0));
    assert!(!original_still_unspent, "accepted parallel conflict must consume the original UTXO exactly once");
    assert_ne!(first_output_exists, second_output_exists, "exactly one conflicting output may enter the virtual UTXO set");
}

const ATOMIC_PRUNING_FINALITY_DEPTH: u64 = 4;
const ATOMIC_PRUNING_DEPTH: u64 = 8;
const ATOMIC_PRUNING_PROOF_M: u64 = 2;

fn atomic_pruning_config_builder(payload_hf_activation_daa_score: u64, process_genesis: bool) -> ConfigBuilder {
    let builder = ConfigBuilder::new(MAINNET_PARAMS).skip_proof_of_work().enable_sanity_checks().edit_consensus_params(|p| {
        p.coinbase_maturity = 0;
        p.payload_hf_activation_daa_score = payload_hf_activation_daa_score;
        p.finality_depth = ATOMIC_PRUNING_FINALITY_DEPTH;
        p.pruning_depth = ATOMIC_PRUNING_DEPTH;
        p.pruning_proof_m = ATOMIC_PRUNING_PROOF_M;
        p.merge_depth = ATOMIC_PRUNING_FINALITY_DEPTH;
        p.mergeset_size_limit = 10;
        p.max_block_parents = 4;
    });

    if process_genesis {
        builder
    } else {
        builder.skip_adding_genesis()
    }
}

fn atomic_pruning_config(payload_hf_activation_daa_score: u64, process_genesis: bool) -> Config {
    atomic_pruning_config_builder(payload_hf_activation_daa_score, process_genesis).build()
}

fn atomic_pruning_archival_config(payload_hf_activation_daa_score: u64, process_genesis: bool) -> Config {
    atomic_pruning_config_builder(payload_hf_activation_daa_score, process_genesis).set_archival().build()
}

async fn mine_empty_blocks(ctx: &mut TestContext, count: usize, nonce_base: u64) -> Hash {
    for offset in 0..count {
        ctx.simulated_time += ctx.consensus.params().target_time_per_block;
        let template = ctx.build_block_template(nonce_base + offset as u64, ctx.simulated_time);
        ctx.validate_and_insert_utxo_valid_block(template.block.to_immutable()).await;
    }
    ctx.consensus.get_sink()
}

async fn mine_asset_create_block(
    ctx: &mut TestContext,
    owner_script: &ScriptPublicKey,
    owner_id: [u8; 32],
    nonce: u64,
    name: &[u8],
    symbol: &[u8],
    amount: u128,
) -> ([u8; 32], Hash) {
    let (funding_outpoint, funding_entry) = find_virtual_utxo_by_script(ctx, owner_script);
    let tx_fee = 10_000u64;
    let create_tx = payload_tx(
        vec![TransactionInput::new(funding_outpoint, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(funding_entry.amount - tx_fee, owner_script.clone())],
        payload_create_asset_with_mint(0, 1, owner_id, name, symbol, amount, owner_id),
    );
    let asset_id = create_tx.id().as_bytes();

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let template = ctx.build_block_template_with_transactions(vec![create_tx], nonce, ctx.simulated_time);
    let block_hash = template.block.header.hash;
    ctx.validate_and_insert_utxo_valid_block(template.block.to_immutable()).await;
    (asset_id, block_hash)
}

async fn mine_token_transfer_block(
    ctx: &mut TestContext,
    owner_script: &ScriptPublicKey,
    asset_id: [u8; 32],
    receiver_id: [u8; 32],
    asset_nonce: u64,
    amount: u128,
    block_nonce: u64,
) -> Hash {
    let (funding_outpoint, funding_entry) = find_virtual_utxo_by_script(ctx, owner_script);
    let tx_fee = 10_000u64;
    let transfer_tx = payload_tx(
        vec![TransactionInput::new(funding_outpoint, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(funding_entry.amount - tx_fee, owner_script.clone())],
        payload_transfer(0, asset_nonce, asset_id, receiver_id, amount),
    );

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let template = ctx.build_block_template_with_transactions(vec![transfer_tx], block_nonce, ctx.simulated_time);
    let block_hash = template.block.header.hash;
    ctx.validate_and_insert_utxo_valid_block(template.block.to_immutable()).await;
    block_hash
}

async fn wait_for_pruning_point_at_or_after_blue_score(ctx: &TestContext, min_blue_score: u64) -> Hash {
    let genesis = ctx.consensus.params().genesis.hash;
    for _ in 0..200 {
        let pruning_point = ctx.consensus.pruning_point();
        let blue_score = ctx.consensus.get_header(pruning_point).unwrap().blue_score;
        if pruning_point != genesis && blue_score >= min_blue_score {
            return pruning_point;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let pruning_point = ctx.consensus.pruning_point();
    let blue_score = ctx.consensus.get_header(pruning_point).unwrap().blue_score;
    panic!(
        "pruning point did not advance to blue_score >= {min_blue_score}; current pruning_point={pruning_point}, blue_score={blue_score}"
    );
}

async fn wait_for_pruning_point_to_stabilize(ctx: &TestContext) -> Hash {
    let mut previous = ctx.consensus.pruning_point();
    let mut stable_samples = 0usize;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        let current = ctx.consensus.pruning_point();
        if current == previous {
            stable_samples += 1;
            if stable_samples >= 3 {
                return current;
            }
        } else {
            previous = current;
            stable_samples = 0;
        }
    }

    previous
}

async fn sync_selected_chain_from_source(source: &TestContext, target: &mut TestContext, low: Hash) -> Hash {
    let chain_path = source.consensus.get_virtual_chain_from_block(low, None).expect("source selected-chain path");
    assert!(chain_path.removed.is_empty(), "sync low point must be on the source selected chain");
    for block_hash in chain_path.added {
        let block = source.consensus.get_block(block_hash).expect("source must retain selected-chain block body");
        target.validate_and_insert_utxo_valid_block(block).await;
    }
    target.consensus.get_sink()
}

fn materialized_pruning_atomic_state(ctx: &TestContext) -> AtomicConsensusState {
    let trusted_data = ctx.consensus.get_pruning_point_anticone_and_trusted_data().unwrap();
    let atomic_state = trusted_data.atomic_state.as_ref().expect("trusted pruning data must carry Atomic state");
    let state_bytes = atomic_state.state_bytes.as_deref().expect("trusted pruning data must carry full Atomic state bytes");
    let state = AtomicConsensusState::try_from_canonical_bytes(state_bytes).expect("trusted pruning Atomic bytes must decode");
    assert_eq!(state.canonical_hash(), atomic_state.state_hash);
    state
}

fn assert_pruning_point_atomic_state(
    ctx: &TestContext,
    pruning_point: Hash,
    expected_asset_id: [u8; 32],
    expected_owner_id: [u8; 32],
    expected_balance: u128,
) -> ([u8; 32], [u8; 32]) {
    let root = ctx.consensus.get_atomic_state_hash(pruning_point).unwrap().expect("pruning point must have an Atomic root record");
    let audit_hash = ctx
        .consensus
        .get_atomic_p2p_token_audit_hash(pruning_point)
        .unwrap()
        .expect("pruning point Atomic state must be materializable for P2P audit");
    let trusted_data = ctx.consensus.get_pruning_point_anticone_and_trusted_data().unwrap();
    let atomic_state = trusted_data.atomic_state.as_ref().expect("trusted pruning data must carry Atomic state");
    assert_eq!(atomic_state.state_hash, root);

    let state_bytes = atomic_state.state_bytes.as_deref().expect("trusted pruning data must carry full Atomic state bytes");
    let imported_state =
        AtomicConsensusState::try_from_canonical_bytes(state_bytes).expect("trusted pruning Atomic bytes must decode");
    assert_eq!(imported_state.canonical_hash(), root);
    assert!(imported_state.assets.contains_key(&expected_asset_id));
    assert_eq!(balance_of(&imported_state, expected_asset_id, expected_owner_id), expected_balance);
    assert_ne!(audit_hash, [0; 32], "token audit hash must be available for materialized pruning point state");
    (root, audit_hash)
}

fn assert_empty_pruning_point_atomic_state(ctx: &TestContext, pruning_point: Hash) {
    let empty_state = AtomicConsensusState::default();
    let empty_root = empty_state.canonical_hash();
    let root =
        ctx.consensus.get_atomic_state_hash(pruning_point).unwrap().expect("post-HF pruning point must have an Atomic root record");
    assert_eq!(root, empty_root);

    let audit_hash = ctx
        .consensus
        .get_atomic_p2p_token_audit_hash(pruning_point)
        .unwrap()
        .expect("empty pruning point Atomic state must be materializable for P2P audit");
    assert_eq!(Some(audit_hash), empty_state.p2p_token_audit_hash());

    let trusted_data = ctx.consensus.get_pruning_point_anticone_and_trusted_data().unwrap();
    let atomic_state = trusted_data.atomic_state.as_ref().expect("trusted pruning data must carry empty Atomic state");
    assert_eq!(atomic_state.state_hash, root);
    let state_bytes = atomic_state.state_bytes.as_deref().expect("trusted pruning data must carry full empty Atomic state bytes");
    let imported_state = AtomicConsensusState::try_from_canonical_bytes(state_bytes).expect("trusted empty Atomic bytes must decode");
    assert_eq!(imported_state.canonical_hash(), empty_root);
    assert!(imported_state.assets.is_empty());
    assert!(imported_state.balances.is_empty());
    assert!(imported_state.next_nonces.is_empty());
    assert!(imported_state.anchor_counts.is_empty());
}

async fn import_pruned_consensus_from_source(source: &TestContext, target_config: &Config) -> TestContext {
    let pruning_point = source.consensus.pruning_point();
    let proof = source.consensus.get_pruning_point_proof().as_ref().clone();
    let pruning_point_headers = source.consensus.pruning_point_headers();
    let trusted_data = source.consensus.get_pruning_point_anticone_and_trusted_data().unwrap();
    let trusted_blocks: Vec<_> = trusted_data
        .anticone
        .iter()
        .copied()
        .map(|hash| {
            let block = source.consensus.get_block(hash).expect("source must retain pruning-point anticone block bodies");
            let ghostdag = source.consensus.get_ghostdag_data(hash).expect("source must retain pruning-point anticone ghostdag");
            TrustedBlock::new(block, ghostdag)
        })
        .collect();

    let mut target = TestContext::new(TestConsensus::new(target_config));
    target.simulated_time = source.simulated_time;
    target.consensus.apply_pruning_proof(proof, &trusted_blocks).expect("target must accept pruning proof");
    target.consensus.import_pruning_points(pruning_point_headers);

    for trusted_block in trusted_blocks {
        target
            .consensus
            .validate_and_insert_trusted_block(trusted_block)
            .virtual_state_task
            .await
            .expect("target must accept trusted pruning anticone block");
    }

    let atomic_state = trusted_data.atomic_state.clone().expect("source pruning trusted data must include Atomic state");
    target
        .consensus
        .import_pruning_point_atomic_state(pruning_point, atomic_state)
        .expect("target must import pruning-point Atomic state before UTXO set");

    let mut imported_multiset = MuHash::new();
    let mut from_outpoint = None;
    let mut skip_first = false;
    loop {
        let chunk = source
            .consensus
            .get_pruning_point_utxos(pruning_point, from_outpoint, 128, skip_first)
            .expect("source pruning-point UTXOs must be available");
        if chunk.is_empty() {
            break;
        }
        from_outpoint = chunk.last().map(|(outpoint, _)| *outpoint);
        skip_first = true;
        target.consensus.append_imported_pruning_point_utxos(&chunk, &mut imported_multiset);
        if chunk.len() < 128 {
            break;
        }
    }
    target
        .consensus
        .import_pruning_point_utxo_set(pruning_point, imported_multiset)
        .expect("target must accept pruning-point UTXO set with imported Atomic state");

    target
}

async fn setup_dual_owner_liquidity_pool() -> (TestContext, DualOwnerLiquidityFixture) {
    let mut ctx = liquidity_test_context();
    let owner_redeem_script = p2sh_redeem_script();
    let second_owner_redeem_script = second_p2sh_redeem_script();
    let owner_script = cryptix_txscript::pay_to_script_hash_script(&owner_redeem_script);
    let second_owner_script = cryptix_txscript::pay_to_script_hash_script(&second_owner_redeem_script);
    let recipient_payload = owner_script.script()[2..34].to_vec();
    let owner_id = atomic_owner_id_from_script(&owner_script).expect("owner id should derive from P2SH");
    let second_owner_id = atomic_owner_id_from_script(&second_owner_script).expect("second owner id should derive from P2SH");
    ctx.miner_data = MinerData::new(owner_script.clone(), vec![]);

    for _ in 0..3 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await;
    }
    let (funding_outpoint, funding_entry) = find_virtual_utxo_by_script(&ctx, &owner_script);

    let max_supply = 1_000_000u128;
    let seed_reserve = SOMPI_PER_CRYPTIX;
    let fee_bps = 100u16;
    let launch_buy_budget = 10 * SOMPI_PER_CRYPTIX;
    let tx_fee = 10_000u64;
    let owner_anchor_value = 50 * SOMPI_PER_CRYPTIX;
    let second_owner_anchor_value = 50 * SOMPI_PER_CRYPTIX;
    let (launch_buy, launch_token_out) = canonical_buy_from_budget(
        max_supply,
        INITIAL_LIQUIDITY_VIRTUAL_CPAY_RESERVES_SOMPI,
        initial_liquidity_virtual_token_reserves(max_supply),
        launch_buy_budget,
        fee_bps,
    );
    let create_vault_value = seed_reserve + launch_buy;
    let create_change_value = funding_entry
        .amount
        .checked_sub(create_vault_value + owner_anchor_value + second_owner_anchor_value + tx_fee)
        .expect("funding should cover liquidity fixture");
    let create_payload = payload_create_liquidity(0, 1, max_supply, seed_reserve, fee_bps, &recipient_payload, launch_buy, 1);
    let create_tx = payload_tx(
        vec![TransactionInput::new(funding_outpoint, p2sh_signature_script_for(&owner_redeem_script), 0, 0)],
        vec![
            TransactionOutput::new(create_vault_value, liquidity_vault_script()),
            TransactionOutput::new(owner_anchor_value, owner_script.clone()),
            TransactionOutput::new(second_owner_anchor_value, second_owner_script.clone()),
            TransactionOutput::new(create_change_value, owner_script.clone()),
        ],
        create_payload,
    );
    let asset_id = create_tx.id().as_bytes();

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let create_template = ctx.build_block_template_with_transactions(vec![create_tx.clone()], 100, ctx.simulated_time);
    let create_block_hash = create_template.block.header.hash;
    ctx.validate_and_insert_block(create_template.block.to_immutable()).await;

    let atomic = ctx.consensus.virtual_atomic_state();
    let asset = atomic.assets.get(&asset_id).expect("liquidity asset should exist");
    let pool = asset.liquidity.as_ref().expect("pool should exist").clone();
    assert_eq!(pool.pool_nonce, 1);

    (
        ctx,
        DualOwnerLiquidityFixture {
            owner_script,
            owner_id,
            second_owner_script,
            second_owner_id,
            asset_id,
            create_block_hash,
            pool,
            owner_anchor: TransactionOutpoint::new(create_tx.id(), 1),
            owner_anchor_value,
            second_owner_anchor: TransactionOutpoint::new(create_tx.id(), 2),
            second_owner_anchor_value,
            launch_token_out,
            tx_fee,
        },
    )
}

fn build_liquidity_buy_tx(
    asset_id: [u8; 32],
    pool: &AtomicLiquidityPoolState,
    auth_anchor: TransactionOutpoint,
    auth_anchor_value: u64,
    auth_script: &ScriptPublicKey,
    auth_signature_script: Vec<u8>,
    auth_nonce: u64,
    buy_in_budget: u64,
    tx_fee: u64,
) -> (Transaction, u128, u64) {
    let (buy_in, token_out) = canonical_buy_from_budget(
        pool.real_token_reserves,
        pool.virtual_cpay_reserves_sompi,
        pool.virtual_token_reserves,
        buy_in_budget,
        pool.fee_bps,
    );
    let vault_value = pool.vault_value_sompi + buy_in;
    let change_value = auth_anchor_value - buy_in - tx_fee;
    let tx = payload_tx(
        vec![
            TransactionInput::new(pool.vault_outpoint, vec![], 0, 0),
            TransactionInput::new(auth_anchor, auth_signature_script, 0, 0),
        ],
        vec![TransactionOutput::new(vault_value, liquidity_vault_script()), TransactionOutput::new(change_value, auth_script.clone())],
        payload_buy_liquidity(1, auth_nonce, asset_id, pool.pool_nonce, buy_in, 1),
    );
    (tx, token_out, vault_value)
}

fn balance_of(atomic: &crate::model::stores::atomic_state::AtomicConsensusState, asset_id: [u8; 32], owner_id: [u8; 32]) -> u128 {
    atomic.balances.get(&AtomicBalanceKey { asset_id, owner_id }).copied().unwrap_or(0)
}

#[tokio::test]
async fn payload_hf_activation_switches_live_without_restart() {
    let activation_daa = 8;
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.coinbase_maturity = 0;
            p.payload_hf_activation_daa_score = activation_daa;
        })
        .build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let owner_script = cryptix_txscript::pay_to_script_hash_script(&p2sh_redeem_script());
    let owner_id = atomic_owner_id_from_script(&owner_script).expect("owner id should derive from P2SH");
    ctx.miner_data = MinerData::new(owner_script.clone(), vec![]);

    for _ in 0..3 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await;
    }
    assert!(ctx.consensus.get_virtual_daa_score() < activation_daa);
    let (funding_outpoint, funding_entry) = find_virtual_utxo_by_script(&ctx, &owner_script);
    let tx_fee = 10_000u64;
    let create_tx = payload_tx(
        vec![TransactionInput::new(funding_outpoint, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(funding_entry.amount - tx_fee, owner_script.clone())],
        payload_create_asset_with_mint(0, 1, owner_id, b"LiveHF", b"LHF", 100, owner_id),
    );
    let asset_id = create_tx.id().as_bytes();

    let mut pre_hf = MutableTransaction::from_tx(create_tx.clone());
    ctx.consensus
        .validate_mempool_transaction(&mut pre_hf, &TransactionValidationArgs::default())
        .expect_err("payload transaction must be rejected before the HF DAA");

    while ctx.consensus.get_virtual_daa_score() < activation_daa {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await;
    }

    let mut post_hf = MutableTransaction::from_tx(create_tx.clone());
    ctx.consensus
        .validate_mempool_transaction(&mut post_hf, &TransactionValidationArgs::default())
        .expect("same running node must accept payload transaction after the HF DAA");

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let create_template = ctx.build_block_template_with_transactions(vec![create_tx], 200, ctx.simulated_time);
    ctx.validate_and_insert_block(create_template.block.to_immutable()).await;
    let create_block_hash = ctx.consensus.get_sink();

    let atomic = ctx.consensus.virtual_atomic_state();
    assert!(atomic.assets.contains_key(&asset_id));
    assert_eq!(balance_of(&atomic, asset_id, owner_id), 100);

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let stabilize_template = ctx.build_block_template(201, ctx.simulated_time);
    ctx.validate_and_insert_block(stabilize_template.block.to_immutable()).await;

    ctx.consensus.clear_atomic_current_store_for_tests();
    ctx.consensus.delete_atomic_state_record_for_tests(create_block_hash);
    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let repair_template = ctx.build_block_template(202, ctx.simulated_time);
    ctx.validate_and_insert_block(repair_template.block.to_immutable()).await;

    let repaired_atomic = ctx.consensus.virtual_atomic_state();
    assert!(repaired_atomic.assets.contains_key(&asset_id));
    assert_eq!(balance_of(&repaired_atomic, asset_id, owner_id), 100);
}

#[tokio::test]
async fn atomic_pruning_post_hf_first_pruning_keeps_full_atomic_state() {
    cryptix_core::log::try_init_logger("info");
    let config = atomic_pruning_config(0, true);
    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let owner_script = cryptix_txscript::pay_to_script_hash_script(&p2sh_redeem_script());
    let owner_id = atomic_owner_id_from_script(&owner_script).expect("owner id should derive from P2SH");
    ctx.miner_data = MinerData::new(owner_script.clone(), vec![]);

    mine_empty_blocks(&mut ctx, 12, 10).await;
    let first_pruning_point = wait_for_pruning_point_at_or_after_blue_score(&ctx, ATOMIC_PRUNING_FINALITY_DEPTH).await;
    assert_empty_pruning_point_atomic_state(&ctx, first_pruning_point);

    let initial_supply = 1_234u128;
    let (asset_id, create_block_hash) =
        mine_asset_create_block(&mut ctx, &owner_script, owner_id, 100, b"PruneHF", b"PHF", initial_supply).await;
    let create_blue_score = ctx.consensus.get_header(create_block_hash).unwrap().blue_score;

    mine_empty_blocks(&mut ctx, 24, 200).await;
    let pruning_point = wait_for_pruning_point_at_or_after_blue_score(&ctx, create_blue_score).await;
    assert_pruning_point_atomic_state(&ctx, pruning_point, asset_id, owner_id, initial_supply);
    ctx.consensus.validate_pruning_points().expect("pruning point chain must remain valid");
}

#[tokio::test]
async fn atomic_pruning_survives_prunings_before_hf_then_post_hf_pruning() {
    cryptix_core::log::try_init_logger("info");
    let activation_daa = 20;
    let config = atomic_pruning_config(activation_daa, true);
    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let owner_script = cryptix_txscript::pay_to_script_hash_script(&p2sh_redeem_script());
    let owner_id = atomic_owner_id_from_script(&owner_script).expect("owner id should derive from P2SH");
    ctx.miner_data = MinerData::new(owner_script.clone(), vec![]);

    mine_empty_blocks(&mut ctx, 18, 300).await;
    let pre_hf_pruning_point = wait_for_pruning_point_at_or_after_blue_score(&ctx, ATOMIC_PRUNING_FINALITY_DEPTH).await;
    assert!(
        ctx.consensus.get_header(pre_hf_pruning_point).unwrap().daa_score < activation_daa,
        "test setup must move at least one pruning point before payload HF activation"
    );

    while ctx.consensus.get_virtual_daa_score() < activation_daa {
        let nonce = 400 + ctx.consensus.get_virtual_daa_score();
        mine_empty_blocks(&mut ctx, 1, nonce).await;
    }

    let initial_supply = 4_321u128;
    let (asset_id, create_block_hash) =
        mine_asset_create_block(&mut ctx, &owner_script, owner_id, 500, b"PostPruneHF", b"PPH", initial_supply).await;
    let create_blue_score = ctx.consensus.get_header(create_block_hash).unwrap().blue_score;

    mine_empty_blocks(&mut ctx, 24, 600).await;
    let post_hf_pruning_point = wait_for_pruning_point_at_or_after_blue_score(&ctx, create_blue_score).await;
    assert_ne!(post_hf_pruning_point, pre_hf_pruning_point);
    assert_pruning_point_atomic_state(&ctx, post_hf_pruning_point, asset_id, owner_id, initial_supply);
    ctx.consensus.validate_pruning_points().expect("mixed pre/post-HF pruning point chain must remain valid");
}

#[tokio::test]
async fn atomic_pruning_sync_imports_full_atomic_state_from_pruned_peer() {
    cryptix_core::log::try_init_logger("info");
    let source_config = atomic_pruning_config(0, true);
    let mut source = TestContext::new(TestConsensus::new(&source_config));
    let owner_script = cryptix_txscript::pay_to_script_hash_script(&p2sh_redeem_script());
    let owner_id = atomic_owner_id_from_script(&owner_script).expect("owner id should derive from P2SH");
    source.miner_data = MinerData::new(owner_script.clone(), vec![]);

    mine_empty_blocks(&mut source, 3, 700).await;
    let initial_supply = 7_777u128;
    let (asset_id, create_block_hash) =
        mine_asset_create_block(&mut source, &owner_script, owner_id, 800, b"SyncPrune", b"SPN", initial_supply).await;
    let create_blue_score = source.consensus.get_header(create_block_hash).unwrap().blue_score;

    mine_empty_blocks(&mut source, 24, 900).await;
    wait_for_pruning_point_at_or_after_blue_score(&source, create_blue_score).await;
    let source_pruning_point = wait_for_pruning_point_to_stabilize(&source).await;
    assert!(
        source.consensus.get_header(source_pruning_point).unwrap().blue_score >= create_blue_score,
        "stable source pruning point must include the Atomic create block"
    );
    let (source_root, source_token_audit_hash) =
        assert_pruning_point_atomic_state(&source, source_pruning_point, asset_id, owner_id, initial_supply);

    let target_config = atomic_pruning_config(0, false);
    let mut target = import_pruned_consensus_from_source(&source, &target_config).await;
    assert_eq!(target.consensus.pruning_point(), source_pruning_point);
    assert_eq!(target.consensus.get_atomic_state_hash(source_pruning_point).unwrap().unwrap(), source_root);
    assert_eq!(target.consensus.get_atomic_p2p_token_audit_hash(source_pruning_point).unwrap().unwrap(), source_token_audit_hash);

    let imported_atomic = target.consensus.virtual_atomic_state();
    assert_eq!(imported_atomic.canonical_hash(), source_root);
    assert!(imported_atomic.assets.contains_key(&asset_id));
    assert_eq!(balance_of(&imported_atomic, asset_id, owner_id), initial_supply);

    target.miner_data = MinerData::new(owner_script.clone(), vec![]);
    let receiver_script = cryptix_txscript::pay_to_script_hash_script(&second_p2sh_redeem_script());
    let receiver_id = atomic_owner_id_from_script(&receiver_script).expect("receiver id should derive from P2SH");
    let (transfer_funding_outpoint, transfer_funding_entry) = find_virtual_utxo_by_script(&target, &owner_script);
    let tx_fee = 10_000u64;
    let transfer_amount = 777u128;
    let transfer_tx = payload_tx(
        vec![TransactionInput::new(transfer_funding_outpoint, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(transfer_funding_entry.amount - tx_fee, owner_script.clone())],
        payload_transfer(0, 1, asset_id, receiver_id, transfer_amount),
    );
    target.simulated_time += target.consensus.params().target_time_per_block;
    let transfer_template = target.build_block_template_with_transactions(vec![transfer_tx], 1_000, target.simulated_time);
    target.validate_and_insert_utxo_valid_block(transfer_template.block.to_immutable()).await;

    let post_sync_atomic = target.consensus.virtual_atomic_state();
    assert_eq!(balance_of(&post_sync_atomic, asset_id, owner_id), initial_supply - transfer_amount);
    assert_eq!(balance_of(&post_sync_atomic, asset_id, receiver_id), transfer_amount);

    mine_empty_blocks(&mut target, 1, 1_001).await;
    let extended_atomic = target.consensus.virtual_atomic_state();
    assert!(extended_atomic.assets.contains_key(&asset_id));
    assert_eq!(balance_of(&extended_atomic, asset_id, owner_id), initial_supply - transfer_amount);
    assert_eq!(balance_of(&extended_atomic, asset_id, receiver_id), transfer_amount);
}

#[tokio::test]
async fn atomic_pruning_sync_after_pre_and_post_hf_prunings_accepts_live_token_blocks() {
    cryptix_core::log::try_init_logger("info");
    let activation_daa = 36;
    let source_config = atomic_pruning_config(activation_daa, true);
    let mut source = TestContext::new(TestConsensus::new(&source_config));
    let owner_script = cryptix_txscript::pay_to_script_hash_script(&p2sh_redeem_script());
    let receiver_script = cryptix_txscript::pay_to_script_hash_script(&second_p2sh_redeem_script());
    let owner_id = atomic_owner_id_from_script(&owner_script).expect("owner id should derive from P2SH");
    let receiver_id = atomic_owner_id_from_script(&receiver_script).expect("receiver id should derive from P2SH");
    source.miner_data = MinerData::new(owner_script.clone(), vec![]);

    mine_empty_blocks(&mut source, 18, 1_100).await;
    let first_pre_hf_pruning_point = wait_for_pruning_point_at_or_after_blue_score(&source, ATOMIC_PRUNING_FINALITY_DEPTH).await;
    assert!(source.consensus.get_header(first_pre_hf_pruning_point).unwrap().daa_score < activation_daa);
    mine_empty_blocks(&mut source, 12, 1_200).await;
    let second_pre_hf_pruning_point = wait_for_pruning_point_at_or_after_blue_score(&source, ATOMIC_PRUNING_FINALITY_DEPTH + 8).await;
    assert_ne!(first_pre_hf_pruning_point, second_pre_hf_pruning_point);
    assert!(source.consensus.get_header(second_pre_hf_pruning_point).unwrap().daa_score < activation_daa);

    while source.consensus.get_virtual_daa_score() < activation_daa {
        let nonce = 1_300 + source.consensus.get_virtual_daa_score();
        mine_empty_blocks(&mut source, 1, nonce).await;
    }

    let initial_supply = 10_000u128;
    let (asset_id, create_block_hash) =
        mine_asset_create_block(&mut source, &owner_script, owner_id, 1_400, b"LongPruneSync", b"LPS", initial_supply).await;
    let create_blue_score = source.consensus.get_header(create_block_hash).unwrap().blue_score;
    let mut owner_expected = initial_supply;
    let mut receiver_expected = 0u128;
    let mut last_token_blue_score = create_blue_score;

    for (idx, amount) in [101u128, 202, 303, 404].into_iter().enumerate() {
        let block_hash =
            mine_token_transfer_block(&mut source, &owner_script, asset_id, receiver_id, idx as u64 + 1, amount, 1_500 + idx as u64)
                .await;
        owner_expected -= amount;
        receiver_expected += amount;
        last_token_blue_score = source.consensus.get_header(block_hash).unwrap().blue_score;
    }

    mine_empty_blocks(&mut source, 24, 1_600).await;
    wait_for_pruning_point_at_or_after_blue_score(&source, last_token_blue_score).await;
    let source_pruning_point = wait_for_pruning_point_to_stabilize(&source).await;
    assert!(source.consensus.get_header(source_pruning_point).unwrap().blue_score >= last_token_blue_score);
    let source_pruning_atomic = materialized_pruning_atomic_state(&source);
    assert!(source_pruning_atomic.assets.contains_key(&asset_id));
    assert_eq!(balance_of(&source_pruning_atomic, asset_id, owner_id), owner_expected);
    assert_eq!(balance_of(&source_pruning_atomic, asset_id, receiver_id), receiver_expected);

    let target_config = atomic_pruning_config(activation_daa, false);
    let mut target = import_pruned_consensus_from_source(&source, &target_config).await;
    assert_eq!(target.consensus.pruning_point(), source_pruning_point);
    assert_eq!(target.consensus.virtual_atomic_state().canonical_hash(), source_pruning_atomic.canonical_hash());

    let synced_sink = sync_selected_chain_from_source(&source, &mut target, source_pruning_point).await;
    assert_eq!(synced_sink, source.consensus.get_sink());
    assert_eq!(target.consensus.virtual_atomic_state().canonical_hash(), source.consensus.virtual_atomic_state().canonical_hash());

    let live_sync_low = synced_sink;
    for (idx, amount) in [11u128, 12, 13, 14, 15, 16].into_iter().enumerate() {
        let asset_nonce = 5 + idx as u64;
        mine_token_transfer_block(&mut source, &owner_script, asset_id, receiver_id, asset_nonce, amount, 1_700 + idx as u64).await;
        owner_expected -= amount;
        receiver_expected += amount;
        if idx % 2 == 0 {
            mine_empty_blocks(&mut source, 1, 1_800 + idx as u64).await;
        }
    }

    let live_synced_sink = sync_selected_chain_from_source(&source, &mut target, live_sync_low).await;
    assert_eq!(live_synced_sink, source.consensus.get_sink());
    let target_atomic = target.consensus.virtual_atomic_state();
    assert_eq!(target_atomic.canonical_hash(), source.consensus.virtual_atomic_state().canonical_hash());
    assert_eq!(balance_of(&target_atomic, asset_id, owner_id), owner_expected);
    assert_eq!(balance_of(&target_atomic, asset_id, receiver_id), receiver_expected);

    mine_empty_blocks(&mut source, 24, 1_900).await;
    wait_for_pruning_point_at_or_after_blue_score(&source, source.consensus.get_header(live_synced_sink).unwrap().blue_score).await;
    let late_source_pruning_point = wait_for_pruning_point_to_stabilize(&source).await;

    let mut late_target = import_pruned_consensus_from_source(&source, &target_config).await;
    let late_pruning_atomic = materialized_pruning_atomic_state(&source);
    assert_eq!(late_target.consensus.virtual_atomic_state().canonical_hash(), late_pruning_atomic.canonical_hash());
    sync_selected_chain_from_source(&source, &mut late_target, late_source_pruning_point).await;
    assert_eq!(
        late_target.consensus.virtual_atomic_state().canonical_hash(),
        source.consensus.virtual_atomic_state().canonical_hash()
    );
}

#[tokio::test]
async fn atomic_pruned_sync_after_pre_hf_pruning_reorgs_live_atomic_branch() {
    cryptix_core::log::try_init_logger("info");
    let activation_daa = 36;
    let source_config = atomic_pruning_config(activation_daa, true);
    let mut source = TestContext::new(TestConsensus::new(&source_config));
    let owner_script = cryptix_txscript::pay_to_script_hash_script(&p2sh_redeem_script());
    let receiver_script = cryptix_txscript::pay_to_script_hash_script(&second_p2sh_redeem_script());
    let owner_id = atomic_owner_id_from_script(&owner_script).expect("owner id should derive from P2SH");
    let receiver_id = atomic_owner_id_from_script(&receiver_script).expect("receiver id should derive from P2SH");
    source.miner_data = MinerData::new(owner_script.clone(), vec![]);

    mine_empty_blocks(&mut source, 18, 2_400).await;
    let first_pre_hf_pruning_point = wait_for_pruning_point_at_or_after_blue_score(&source, ATOMIC_PRUNING_FINALITY_DEPTH).await;
    assert!(source.consensus.get_header(first_pre_hf_pruning_point).unwrap().daa_score < activation_daa);
    mine_empty_blocks(&mut source, 12, 2_500).await;
    let second_pre_hf_pruning_point = wait_for_pruning_point_at_or_after_blue_score(&source, ATOMIC_PRUNING_FINALITY_DEPTH + 8).await;
    assert_ne!(first_pre_hf_pruning_point, second_pre_hf_pruning_point);
    assert!(source.consensus.get_header(second_pre_hf_pruning_point).unwrap().daa_score < activation_daa);

    while source.consensus.get_virtual_daa_score() < activation_daa {
        let nonce = 2_600 + source.consensus.get_virtual_daa_score();
        mine_empty_blocks(&mut source, 1, nonce).await;
    }

    let initial_supply = 20_000u128;
    let (asset_id, create_block_hash) =
        mine_asset_create_block(&mut source, &owner_script, owner_id, 2_700, b"PrunedReorg", b"PRG", initial_supply).await;
    let mut owner_expected = initial_supply;
    let mut receiver_expected = 0u128;
    let mut last_token_blue_score = source.consensus.get_header(create_block_hash).unwrap().blue_score;

    for (idx, amount) in [250u128, 350, 450, 550].into_iter().enumerate() {
        let block_hash =
            mine_token_transfer_block(&mut source, &owner_script, asset_id, receiver_id, idx as u64 + 1, amount, 2_800 + idx as u64)
                .await;
        owner_expected -= amount;
        receiver_expected += amount;
        last_token_blue_score = source.consensus.get_header(block_hash).unwrap().blue_score;
    }

    mine_empty_blocks(&mut source, 24, 2_900).await;
    wait_for_pruning_point_at_or_after_blue_score(&source, last_token_blue_score).await;
    let source_pruning_point = wait_for_pruning_point_to_stabilize(&source).await;
    assert!(source.consensus.get_header(source_pruning_point).unwrap().blue_score >= last_token_blue_score);
    let source_pruning_atomic = materialized_pruning_atomic_state(&source);
    assert_eq!(balance_of(&source_pruning_atomic, asset_id, owner_id), owner_expected);
    assert_eq!(balance_of(&source_pruning_atomic, asset_id, receiver_id), receiver_expected);

    let target_config = atomic_pruning_config(activation_daa, false);
    let mut target = import_pruned_consensus_from_source(&source, &target_config).await;
    assert_eq!(target.consensus.pruning_point(), source_pruning_point);
    assert_eq!(target.consensus.virtual_atomic_state().canonical_hash(), source_pruning_atomic.canonical_hash());

    let fork_parent = sync_selected_chain_from_source(&source, &mut target, source_pruning_point).await;
    assert_eq!(fork_parent, source.consensus.get_sink());
    assert_eq!(target.consensus.virtual_atomic_state().canonical_hash(), source.consensus.virtual_atomic_state().canonical_hash());

    target.miner_data = MinerData::new(owner_script.clone(), vec![]);
    let tx_fee = 10_000u64;
    let losing_amount = 111u128;
    let winning_amount = 777u128;
    let next_asset_nonce = 5u64;

    let losing_utxo = find_virtual_utxo_by_script(&target, &owner_script);
    let winning_utxo = find_virtual_utxo_by_script(&source, &owner_script);
    assert_eq!(losing_utxo.0, winning_utxo.0, "branches should compete over the same CPAY UTXO at the fork point");
    assert_eq!(losing_utxo.1.amount, winning_utxo.1.amount);

    let losing_transfer = payload_tx(
        vec![TransactionInput::new(losing_utxo.0, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(losing_utxo.1.amount - tx_fee, owner_script.clone())],
        payload_transfer(0, next_asset_nonce, asset_id, receiver_id, losing_amount),
    );
    target.simulated_time += target.consensus.params().target_time_per_block;
    let losing_block = target.build_utxo_valid_block_with_parents_and_transactions(
        vec![fork_parent],
        vec![losing_transfer],
        3_000,
        target.simulated_time,
    );
    target.validate_and_insert_utxo_valid_block(losing_block.to_immutable()).await;

    let target_losing_atomic = target.consensus.virtual_atomic_state();
    assert_eq!(balance_of(&target_losing_atomic, asset_id, owner_id), owner_expected - losing_amount);
    assert_eq!(balance_of(&target_losing_atomic, asset_id, receiver_id), receiver_expected + losing_amount);

    let winning_transfer = payload_tx(
        vec![TransactionInput::new(winning_utxo.0, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(winning_utxo.1.amount - tx_fee, owner_script.clone())],
        payload_transfer(0, next_asset_nonce, asset_id, receiver_id, winning_amount),
    );
    source.simulated_time += source.consensus.params().target_time_per_block;
    let winning_block = source.build_utxo_valid_block_with_parents_and_transactions(
        vec![fork_parent],
        vec![winning_transfer],
        3_100,
        source.simulated_time,
    );
    let mut winning_tip = winning_block.header.hash;
    source.validate_and_insert_utxo_valid_block(winning_block.to_immutable()).await;

    for nonce in 3_101..3_104 {
        source.simulated_time += source.consensus.params().target_time_per_block;
        let extension =
            source.build_utxo_valid_block_with_parents_and_transactions(vec![winning_tip], vec![], nonce, source.simulated_time);
        winning_tip = extension.header.hash;
        source.validate_and_insert_utxo_valid_block(extension.to_immutable()).await;
    }
    assert!(source.consensus.reachability_service().is_chain_ancestor_of(winning_tip, source.consensus.get_sink()));

    let reorged_sink = sync_selected_chain_from_source(&source, &mut target, fork_parent).await;
    assert_eq!(reorged_sink, source.consensus.get_sink());
    let target_atomic = target.consensus.virtual_atomic_state();
    assert_eq!(target_atomic.canonical_hash(), source.consensus.virtual_atomic_state().canonical_hash());
    assert_eq!(balance_of(&target_atomic, asset_id, owner_id), owner_expected - winning_amount);
    assert_eq!(balance_of(&target_atomic, asset_id, receiver_id), receiver_expected + winning_amount);
    assert_ne!(balance_of(&target_atomic, asset_id, receiver_id), receiver_expected + losing_amount);
    assert_eq!(target_atomic.next_nonces.get(&AtomicNonceKey::asset(owner_id, asset_id)), Some(&(next_asset_nonce + 1)));
    target.consensus.validate_pruning_points().expect("mixed pre/post-HF pruning point chain must remain valid after reorg");

    let reorged_sink_blue_score = target.consensus.get_header(reorged_sink).unwrap().blue_score;
    mine_empty_blocks(&mut target, 24, 3_200).await;
    wait_for_pruning_point_at_or_after_blue_score(&target, reorged_sink_blue_score).await;
    let post_reorg_pruning_point = wait_for_pruning_point_to_stabilize(&target).await;
    let post_reorg_pruning_atomic = materialized_pruning_atomic_state(&target);
    assert!(target.consensus.get_header(post_reorg_pruning_point).unwrap().blue_score >= reorged_sink_blue_score);
    assert_eq!(
        post_reorg_pruning_atomic.canonical_hash(),
        target.consensus.get_atomic_state_hash(post_reorg_pruning_point).unwrap().unwrap()
    );
    assert_eq!(balance_of(&post_reorg_pruning_atomic, asset_id, owner_id), owner_expected - winning_amount);
    assert_eq!(balance_of(&post_reorg_pruning_atomic, asset_id, receiver_id), receiver_expected + winning_amount);
    assert_eq!(post_reorg_pruning_atomic.next_nonces.get(&AtomicNonceKey::asset(owner_id, asset_id)), Some(&(next_asset_nonce + 1)));
    target.consensus.validate_pruning_points().expect("post-reorg Atomic pruning point chain must remain valid");
}

#[tokio::test]
async fn atomic_archival_peer_provides_full_atomic_pruning_state_for_pruned_sync() {
    cryptix_core::log::try_init_logger("info");
    let source_config = atomic_pruning_archival_config(0, true);
    let mut source = TestContext::new(TestConsensus::new(&source_config));
    let owner_script = cryptix_txscript::pay_to_script_hash_script(&p2sh_redeem_script());
    let owner_id = atomic_owner_id_from_script(&owner_script).expect("owner id should derive from P2SH");
    source.miner_data = MinerData::new(owner_script.clone(), vec![]);

    mine_empty_blocks(&mut source, 3, 2_100).await;
    let initial_supply = 8_888u128;
    let (asset_id, create_block_hash) =
        mine_asset_create_block(&mut source, &owner_script, owner_id, 2_200, b"ArchiveSync", b"ARS", initial_supply).await;
    let create_blue_score = source.consensus.get_header(create_block_hash).unwrap().blue_score;

    mine_empty_blocks(&mut source, 28, 2_300).await;
    wait_for_pruning_point_at_or_after_blue_score(&source, create_blue_score).await;
    let source_pruning_point = wait_for_pruning_point_to_stabilize(&source).await;
    assert!(source.consensus.get_header(source_pruning_point).unwrap().blue_score >= create_blue_score);
    assert_pruning_point_atomic_state(&source, source_pruning_point, asset_id, owner_id, initial_supply);
    assert!(
        source.consensus.get_block(create_block_hash).is_ok(),
        "archival source must retain old block bodies after pruning-point movement"
    );

    let target_config = atomic_pruning_config(0, false);
    let mut target = import_pruned_consensus_from_source(&source, &target_config).await;
    assert_eq!(target.consensus.pruning_point(), source_pruning_point);
    assert_eq!(target.consensus.virtual_atomic_state().canonical_hash(), materialized_pruning_atomic_state(&source).canonical_hash());
    sync_selected_chain_from_source(&source, &mut target, source_pruning_point).await;
    assert_eq!(target.consensus.virtual_atomic_state().canonical_hash(), source.consensus.virtual_atomic_state().canonical_hash());
}

#[tokio::test]
async fn missing_current_store_and_missing_selected_chain_delta_rebuilds_from_virtual_utxo_when_root_matches() {
    let activation_daa = 8;
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.coinbase_maturity = 0;
            p.payload_hf_activation_daa_score = activation_daa;
        })
        .build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let owner_script = cryptix_txscript::pay_to_script_hash_script(&p2sh_redeem_script());
    ctx.miner_data = MinerData::new(owner_script.clone(), vec![]);

    while ctx.consensus.get_virtual_daa_score() < activation_daa {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await;
    }

    let (anchor_outpoint, anchor_entry) = find_virtual_utxo_by_script(&ctx, &owner_script);
    let tx_fee = 10_000u64;
    let mut anchor_tx = Transaction::new(
        TX_VERSION,
        vec![TransactionInput::new(anchor_outpoint, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(anchor_entry.amount - tx_fee, owner_script.clone())],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );
    anchor_tx.finalize();
    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let anchor_template = ctx.build_block_template_with_transactions(vec![anchor_tx], 300, ctx.simulated_time);
    ctx.validate_and_insert_block(anchor_template.block.to_immutable()).await;

    let missing_delta_block = ctx.consensus.get_sink();
    ctx.consensus.clear_atomic_current_store_for_tests();
    ctx.consensus.delete_atomic_state_record_for_tests(missing_delta_block);

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let repair_template = ctx.build_block_template(301, ctx.simulated_time);
    ctx.validate_and_insert_block(repair_template.block.to_immutable()).await;

    let rebuilt = ctx.consensus.virtual_atomic_state();
    let owner_id = atomic_owner_id_from_script(&owner_script).expect("owner id should derive from P2SH");
    assert!(rebuilt.has_anchor_count(&owner_id));
}

#[tokio::test]
async fn atomic_same_owner_different_assets_can_advance_in_same_block() {
    let mut ctx = liquidity_test_context();
    let owner_script = cryptix_txscript::pay_to_script_hash_script(&p2sh_redeem_script());
    let receiver_script = cryptix_txscript::pay_to_script_hash_script(&second_p2sh_redeem_script());
    let owner_id = atomic_owner_id_from_script(&owner_script).expect("owner id should derive from P2SH");
    let receiver_id = atomic_owner_id_from_script(&receiver_script).expect("receiver id should derive from P2SH");
    ctx.miner_data = MinerData::new(owner_script.clone(), vec![]);

    for _ in 0..6 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await;
    }
    let utxos = find_virtual_utxos_by_script(&ctx, &owner_script, 4);
    let tx_fee = 10_000u64;

    let create_a = payload_tx(
        vec![TransactionInput::new(utxos[0].0, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(utxos[0].1.amount - tx_fee, owner_script.clone())],
        payload_create_asset_with_mint(0, 1, owner_id, b"AssetA", b"ATKA", 1_000, owner_id),
    );
    let asset_a = create_a.id().as_bytes();
    let create_b = payload_tx(
        vec![TransactionInput::new(utxos[1].0, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(utxos[1].1.amount - tx_fee, owner_script.clone())],
        payload_create_asset_with_mint(0, 2, owner_id, b"AssetB", b"ATKB", 2_000, owner_id),
    );
    let asset_b = create_b.id().as_bytes();

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let create_template = ctx.build_block_template_with_transactions(vec![create_a, create_b], 20, ctx.simulated_time);
    ctx.validate_and_insert_block(create_template.block.to_immutable()).await;

    let transfer_a = payload_tx(
        vec![TransactionInput::new(utxos[2].0, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(utxos[2].1.amount - tx_fee, owner_script.clone())],
        payload_transfer(0, 1, asset_a, receiver_id, 100),
    );
    let transfer_b = payload_tx(
        vec![TransactionInput::new(utxos[3].0, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(utxos[3].1.amount - tx_fee, owner_script.clone())],
        payload_transfer(0, 1, asset_b, receiver_id, 200),
    );

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let transfer_template = ctx.build_block_template_with_transactions(vec![transfer_a, transfer_b], 21, ctx.simulated_time);
    ctx.validate_and_insert_block(transfer_template.block.to_immutable()).await;

    let atomic = ctx.consensus.virtual_atomic_state();
    assert_eq!(balance_of(&atomic, asset_a, owner_id), 900);
    assert_eq!(balance_of(&atomic, asset_a, receiver_id), 100);
    assert_eq!(balance_of(&atomic, asset_b, owner_id), 1_800);
    assert_eq!(balance_of(&atomic, asset_b, receiver_id), 200);
    assert_eq!(atomic.next_nonces.get(&AtomicNonceKey::owner(owner_id)), Some(&3));
    assert_eq!(atomic.next_nonces.get(&AtomicNonceKey::asset(owner_id, asset_a)), Some(&2));
    assert_eq!(atomic.next_nonces.get(&AtomicNonceKey::asset(owner_id, asset_b)), Some(&2));
}

#[tokio::test]
async fn atomic_same_asset_sequential_nonces_can_advance_in_same_block() {
    let mut ctx = liquidity_test_context();
    let owner_script = cryptix_txscript::pay_to_script_hash_script(&p2sh_redeem_script());
    let receiver_script = cryptix_txscript::pay_to_script_hash_script(&second_p2sh_redeem_script());
    let owner_id = atomic_owner_id_from_script(&owner_script).expect("owner id should derive from P2SH");
    let receiver_id = atomic_owner_id_from_script(&receiver_script).expect("receiver id should derive from P2SH");
    ctx.miner_data = MinerData::new(owner_script.clone(), vec![]);

    for _ in 0..5 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await;
    }
    let utxos = find_virtual_utxos_by_script(&ctx, &owner_script, 3);
    let tx_fee = 10_000u64;

    let create = payload_tx(
        vec![TransactionInput::new(utxos[0].0, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(utxos[0].1.amount - tx_fee, owner_script.clone())],
        payload_create_asset_with_mint(0, 1, owner_id, b"SeqAsset", b"SEQA", 1_000, owner_id),
    );
    let asset_id = create.id().as_bytes();

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let create_template = ctx.build_block_template_with_transactions(vec![create], 30, ctx.simulated_time);
    ctx.validate_and_insert_block(create_template.block.to_immutable()).await;

    let transfer_1 = payload_tx(
        vec![TransactionInput::new(utxos[1].0, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(utxos[1].1.amount - tx_fee, owner_script.clone())],
        payload_transfer(0, 1, asset_id, receiver_id, 100),
    );
    let transfer_2 = payload_tx(
        vec![TransactionInput::new(utxos[2].0, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(utxos[2].1.amount - tx_fee, owner_script.clone())],
        payload_transfer(0, 2, asset_id, receiver_id, 200),
    );

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let transfer_template = ctx.build_block_template_with_transactions(vec![transfer_2, transfer_1], 31, ctx.simulated_time);
    ctx.validate_and_insert_block(transfer_template.block.to_immutable()).await;

    let atomic = ctx.consensus.virtual_atomic_state();
    assert_eq!(balance_of(&atomic, asset_id, owner_id), 700);
    assert_eq!(balance_of(&atomic, asset_id, receiver_id), 300);
    assert_eq!(atomic.next_nonces.get(&AtomicNonceKey::owner(owner_id)), Some(&2));
    assert_eq!(atomic.next_nonces.get(&AtomicNonceKey::asset(owner_id, asset_id)), Some(&3));
}

#[tokio::test]
async fn atomic_batch_invalid_tx_does_not_poison_valid_nonce_chain() {
    let mut ctx = liquidity_test_context();
    let owner_script = cryptix_txscript::pay_to_script_hash_script(&p2sh_redeem_script());
    let receiver_script = cryptix_txscript::pay_to_script_hash_script(&second_p2sh_redeem_script());
    let owner_id = atomic_owner_id_from_script(&owner_script).expect("owner id should derive from P2SH");
    let receiver_id = atomic_owner_id_from_script(&receiver_script).expect("receiver id should derive from P2SH");
    ctx.miner_data = MinerData::new(owner_script.clone(), vec![]);

    for _ in 0..5 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await;
    }
    let utxos = find_virtual_utxos_by_script(&ctx, &owner_script, 4);
    let tx_fee = 10_000u64;

    let create = payload_tx(
        vec![TransactionInput::new(utxos[0].0, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(utxos[0].1.amount - tx_fee, owner_script.clone())],
        payload_create_asset_with_mint(0, 1, owner_id, b"BatchAsset", b"BATA", 1_000, owner_id),
    );
    let asset_id = create.id().as_bytes();

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let create_template = ctx.build_block_template_with_transactions(vec![create], 32, ctx.simulated_time);
    ctx.validate_and_insert_block(create_template.block.to_immutable()).await;

    let transfer_1 = payload_tx(
        vec![TransactionInput::new(utxos[1].0, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(utxos[1].1.amount - tx_fee, owner_script.clone())],
        payload_transfer(0, 1, asset_id, receiver_id, 100),
    );
    let invalid_transfer_2 = payload_tx(
        vec![TransactionInput::new(utxos[2].0, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(utxos[2].1.amount - tx_fee, owner_script.clone())],
        payload_transfer(0, 2, asset_id, receiver_id, 2_000),
    );
    let valid_transfer_2 = payload_tx(
        vec![TransactionInput::new(utxos[3].0, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(utxos[3].1.amount - tx_fee, owner_script.clone())],
        payload_transfer(0, 2, asset_id, receiver_id, 200),
    );

    let mut batch = vec![
        MutableTransaction::with_entries(Arc::new(invalid_transfer_2), vec![utxos[2].1.clone()]),
        MutableTransaction::with_entries(Arc::new(valid_transfer_2), vec![utxos[3].1.clone()]),
        MutableTransaction::with_entries(Arc::new(transfer_1), vec![utxos[1].1.clone()]),
    ];
    let results = ctx.consensus.validate_mempool_transactions_in_parallel(&mut batch, &TransactionValidationBatchArgs::default());

    assert!(results[0].is_err(), "invalid nonce-2 transfer must be rejected");
    assert!(results[1].is_ok(), "valid nonce-2 transfer must survive a bad sibling tx: {results:?}");
    assert!(results[2].is_ok(), "nonce-1 transfer must validate and feed the nonce chain: {results:?}");
}

#[tokio::test]
async fn atomic_mempool_pressure_orders_mixed_payload_and_native_batch() {
    let mut ctx = liquidity_test_context();
    let owner_script = cryptix_txscript::pay_to_script_hash_script(&p2sh_redeem_script());
    let receiver_script = cryptix_txscript::pay_to_script_hash_script(&second_p2sh_redeem_script());
    let owner_id = atomic_owner_id_from_script(&owner_script).expect("owner id should derive from P2SH");
    let receiver_id = atomic_owner_id_from_script(&receiver_script).expect("receiver id should derive from P2SH");
    ctx.miner_data = MinerData::new(owner_script.clone(), vec![]);

    let transfer_count = 48usize;
    let messenger_count = 12usize;
    let native_count = 12usize;
    let funding_count = 1 + transfer_count + messenger_count + native_count;
    for _ in 0..(funding_count + 4) {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await;
    }
    let utxos = find_virtual_utxos_by_script(&ctx, &owner_script, funding_count);
    let tx_fee = 10_000u64;
    let minted = 10_000u128;

    let create = payload_tx(
        vec![TransactionInput::new(utxos[0].0, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(utxos[0].1.amount - tx_fee, owner_script.clone())],
        payload_create_asset_with_mint(0, 1, owner_id, b"Pressure", b"PRS", minted, owner_id),
    );
    let asset_id = create.id().as_bytes();
    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let create_template = ctx.build_block_template_with_transactions(vec![create], 9_000, ctx.simulated_time);
    ctx.validate_and_insert_utxo_valid_block(create_template.block.to_immutable()).await;

    let atomic_before = ctx.consensus.virtual_atomic_state();
    let root_before = atomic_before.canonical_hash();
    assert_eq!(balance_of(&atomic_before, asset_id, owner_id), minted);
    assert_eq!(balance_of(&atomic_before, asset_id, receiver_id), 0);

    let mut batch = Vec::new();
    let mut expected_transfer_total = 0u128;
    for i in 0..transfer_count {
        let nonce = (transfer_count - i) as u64;
        let amount = 1 + u128::from(nonce % 5);
        expected_transfer_total += amount;
        let utxo = &utxos[1 + i];
        let tx = payload_tx(
            vec![TransactionInput::new(utxo.0, p2sh_signature_script(), 0, 0)],
            vec![TransactionOutput::new(utxo.1.amount - tx_fee, owner_script.clone())],
            payload_transfer(0, nonce, asset_id, receiver_id, amount),
        );
        batch.push(MutableTransaction::from_tx(tx));
    }
    for i in 0..messenger_count {
        let utxo = &utxos[1 + transfer_count + i];
        let payload = format!("MSG:pressure:{i}:{}", "x".repeat(192)).into_bytes();
        let tx = payload_tx(
            vec![TransactionInput::new(utxo.0, p2sh_signature_script(), 0, 0)],
            vec![TransactionOutput::new(utxo.1.amount - tx_fee, owner_script.clone())],
            payload,
        );
        batch.push(MutableTransaction::from_tx(tx));
    }
    for i in 0..native_count {
        let utxo = &utxos[1 + transfer_count + messenger_count + i];
        let tx = native_tx(
            vec![TransactionInput::new(utxo.0, p2sh_signature_script(), 0, 0)],
            vec![TransactionOutput::new(utxo.1.amount - tx_fee, owner_script.clone())],
        );
        batch.push(MutableTransaction::from_tx(tx));
    }

    let populate_results = ctx.consensus.populate_mempool_transactions_in_parallel(&mut batch);
    assert!(populate_results.iter().all(Result::is_ok), "pressure batch UTXO population failed: {populate_results:?}");
    let results = ctx.consensus.validate_mempool_transactions_in_parallel(&mut batch, &TransactionValidationBatchArgs::default());
    assert!(results.iter().all(Result::is_ok), "pressure batch should validate deterministically: {results:?}");
    assert!(expected_transfer_total < minted);

    let atomic_after = ctx.consensus.virtual_atomic_state();
    assert_eq!(atomic_after.canonical_hash(), root_before, "mempool pressure validation must not mutate virtual Atomic state");
    assert_eq!(balance_of(&atomic_after, asset_id, owner_id), minted);
    assert_eq!(balance_of(&atomic_after, asset_id, receiver_id), 0);
}

#[tokio::test]
async fn atomic_uncapped_mint_overflow_is_rejected_without_state_mutation() {
    let mut ctx = liquidity_test_context();
    let owner_script = cryptix_txscript::pay_to_script_hash_script(&p2sh_redeem_script());
    let owner_id = atomic_owner_id_from_script(&owner_script).expect("owner id should derive from P2SH");
    ctx.miner_data = MinerData::new(owner_script.clone(), vec![]);

    for _ in 0..5 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await;
    }
    let tx_fee = 10_000u64;
    let (create_outpoint, create_entry) = find_virtual_utxo_by_script(&ctx, &owner_script);
    let create_tx = payload_tx(
        vec![TransactionInput::new(create_outpoint, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(create_entry.amount - tx_fee, owner_script.clone())],
        payload_create_asset_with_mint(0, 1, owner_id, b"UncappedMax", b"UMX", u128::MAX, owner_id),
    );
    let asset_id = create_tx.id().as_bytes();

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let create_template = ctx.build_block_template_with_transactions(vec![create_tx], 9_200, ctx.simulated_time);
    ctx.validate_and_insert_utxo_valid_block(create_template.block.to_immutable()).await;

    let atomic_before = ctx.consensus.virtual_atomic_state();
    let root_before = atomic_before.canonical_hash();
    assert_eq!(balance_of(&atomic_before, asset_id, owner_id), u128::MAX);
    assert_eq!(atomic_before.assets.get(&asset_id).expect("asset should exist").total_supply, u128::MAX);

    let (mint_outpoint, mint_entry) = find_virtual_utxo_by_script(&ctx, &owner_script);
    let overflow_mint_tx = payload_tx(
        vec![TransactionInput::new(mint_outpoint, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(mint_entry.amount - tx_fee, owner_script.clone())],
        payload_mint(0, 1, asset_id, owner_id, 1),
    );

    let mut mempool_tx = MutableTransaction::from_tx(overflow_mint_tx.clone());
    let mempool_err = ctx
        .consensus
        .validate_mempool_transaction(&mut mempool_tx, &TransactionValidationArgs::default())
        .expect_err("uncapped mint above u128::MAX must be rejected by mempool validation");
    assert!(format!("{mempool_err:?}").contains("supply overflow"), "unexpected mempool error: {mempool_err:?}");
    assert_eq!(ctx.consensus.virtual_atomic_state().canonical_hash(), root_before);

    let template_result = ctx.consensus.build_block_template(
        ctx.miner_data.clone(),
        Box::new(OnetimeTxSelector::new(vec![overflow_mint_tx])),
        TemplateBuildMode::Standard,
    );
    assert!(template_result.is_err(), "uncapped mint overflow must not be mineable into a block template");

    let atomic_after = ctx.consensus.virtual_atomic_state();
    assert_eq!(atomic_after.canonical_hash(), root_before);
    assert_eq!(balance_of(&atomic_after, asset_id, owner_id), u128::MAX);
    assert_eq!(atomic_after.assets.get(&asset_id).expect("asset should still exist").total_supply, u128::MAX);
}

#[tokio::test]
async fn atomic_standard_token_auth_rejects_fake_owner_transfer_burn_and_mint() {
    let mut ctx = liquidity_test_context();
    let owner_script = cryptix_txscript::pay_to_script_hash_script(&p2sh_redeem_script());
    let second_owner_script = cryptix_txscript::pay_to_script_hash_script(&second_p2sh_redeem_script());
    let owner_id = atomic_owner_id_from_script(&owner_script).expect("owner id should derive from P2SH");
    let second_owner_id = atomic_owner_id_from_script(&second_owner_script).expect("second owner id should derive from P2SH");
    ctx.miner_data = MinerData::new(owner_script.clone(), vec![]);

    for _ in 0..4 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await;
    }
    let tx_fee = 10_000u64;
    let (create_outpoint, create_entry) = find_virtual_utxo_by_script(&ctx, &owner_script);
    let second_owner_anchor_value = SOMPI_PER_CRYPTIX;
    let create_change_value = create_entry
        .amount
        .checked_sub(tx_fee + 3 * second_owner_anchor_value)
        .expect("create input should fund owner change and fake-owner anchors");
    let create_tx = payload_tx(
        vec![TransactionInput::new(create_outpoint, p2sh_signature_script(), 0, 0)],
        vec![
            TransactionOutput::new(create_change_value, owner_script.clone()),
            TransactionOutput::new(second_owner_anchor_value, second_owner_script.clone()),
            TransactionOutput::new(second_owner_anchor_value, second_owner_script.clone()),
            TransactionOutput::new(second_owner_anchor_value, second_owner_script.clone()),
        ],
        payload_create_asset_with_mint(0, 1, owner_id, b"AuthToken", b"AUTH", 1_000, owner_id),
    );
    let asset_id = create_tx.id().as_bytes();

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let create_template = ctx.build_block_template_with_transactions(vec![create_tx], 9_300, ctx.simulated_time);
    ctx.validate_and_insert_utxo_valid_block(create_template.block.to_immutable()).await;

    let second_utxos = find_virtual_utxos_by_script(&ctx, &second_owner_script, 3);

    let atomic_before = ctx.consensus.virtual_atomic_state();
    let root_before = atomic_before.canonical_hash();
    assert_eq!(balance_of(&atomic_before, asset_id, owner_id), 1_000);
    assert_eq!(balance_of(&atomic_before, asset_id, second_owner_id), 0);

    let build_second_owner_tx = |utxo: &(TransactionOutpoint, UtxoEntry), payload| -> Transaction {
        payload_tx(
            vec![TransactionInput::new(utxo.0, p2sh_signature_script_for(&second_p2sh_redeem_script()), 0, 0)],
            vec![TransactionOutput::new(utxo.1.amount - tx_fee, second_owner_script.clone())],
            payload,
        )
    };

    let fake_transfer = build_second_owner_tx(&second_utxos[0], payload_transfer(0, 1, asset_id, owner_id, 1));
    let mut fake_transfer_mtx = MutableTransaction::from_tx(fake_transfer);
    let transfer_err = ctx
        .consensus
        .validate_mempool_transaction(&mut fake_transfer_mtx, &TransactionValidationArgs::default())
        .expect_err("non-owner must not transfer another owner's token balance");
    assert!(format!("{transfer_err:?}").contains("insufficient balance"), "unexpected transfer error: {transfer_err:?}");
    assert_eq!(ctx.consensus.virtual_atomic_state().canonical_hash(), root_before);

    let fake_burn = build_second_owner_tx(&second_utxos[1], payload_burn(0, 1, asset_id, 1));
    let mut fake_burn_mtx = MutableTransaction::from_tx(fake_burn);
    let burn_err = ctx
        .consensus
        .validate_mempool_transaction(&mut fake_burn_mtx, &TransactionValidationArgs::default())
        .expect_err("non-owner must not burn another owner's token balance");
    assert!(format!("{burn_err:?}").contains("insufficient balance"), "unexpected burn error: {burn_err:?}");
    assert_eq!(ctx.consensus.virtual_atomic_state().canonical_hash(), root_before);

    let fake_mint = build_second_owner_tx(&second_utxos[2], payload_mint(0, 1, asset_id, second_owner_id, 1));
    let mut fake_mint_mtx = MutableTransaction::from_tx(fake_mint);
    let mint_err = ctx
        .consensus
        .validate_mempool_transaction(&mut fake_mint_mtx, &TransactionValidationArgs::default())
        .expect_err("non-authority must not mint a standard token");
    assert!(format!("{mint_err:?}").contains("not mint authority"), "unexpected mint error: {mint_err:?}");

    let atomic_after = ctx.consensus.virtual_atomic_state();
    assert_eq!(atomic_after.canonical_hash(), root_before);
    assert_eq!(balance_of(&atomic_after, asset_id, owner_id), 1_000);
    assert_eq!(balance_of(&atomic_after, asset_id, second_owner_id), 0);
    assert_eq!(atomic_after.assets.get(&asset_id).expect("asset should exist").total_supply, 1_000);
}

#[tokio::test]
async fn atomic_liquidity_token_rejects_decimals_mint_and_burn_but_allows_transfer() {
    let (ctx, fixture) = setup_dual_owner_liquidity_pool().await;

    let atomic_before = ctx.consensus.virtual_atomic_state();
    let root_before = atomic_before.canonical_hash();
    let asset = atomic_before.assets.get(&fixture.asset_id).expect("liquidity asset should exist");
    assert_eq!(asset.asset_class, AtomicAssetClass::Liquidity);
    assert_eq!(asset.decimals, 0);
    assert_eq!(asset.mint_authority_owner_id, [0u8; 32]);
    assert_eq!(balance_of(&atomic_before, fixture.asset_id, fixture.owner_id), fixture.launch_token_out);
    assert_eq!(balance_of(&atomic_before, fixture.asset_id, fixture.second_owner_id), 0);

    let recipient_payload = fixture.owner_script.script()[2..34].to_vec();
    let max_supply = 1_000_000u128;
    let seed_reserve = SOMPI_PER_CRYPTIX;
    let fee_bps = 100u16;
    let launch_buy_budget = 10 * SOMPI_PER_CRYPTIX;
    let (launch_buy, _) = canonical_buy_from_budget(
        max_supply,
        INITIAL_LIQUIDITY_VIRTUAL_CPAY_RESERVES_SOMPI,
        initial_liquidity_virtual_token_reserves(max_supply),
        launch_buy_budget,
        fee_bps,
    );
    let create_vault_value = seed_reserve + launch_buy;
    let mut bad_decimals_payload =
        payload_create_liquidity(0, 2, max_supply, seed_reserve, fee_bps, &recipient_payload, launch_buy, 1);
    bad_decimals_payload[18] = 1;
    let bad_decimals_create = payload_tx(
        vec![TransactionInput::new(fixture.owner_anchor, p2sh_signature_script(), 0, 0)],
        vec![
            TransactionOutput::new(create_vault_value, liquidity_vault_script()),
            TransactionOutput::new(fixture.owner_anchor_value - create_vault_value - fixture.tx_fee, fixture.owner_script.clone()),
        ],
        bad_decimals_payload,
    );
    let mut bad_decimals_mtx = MutableTransaction::from_tx(bad_decimals_create);
    let bad_decimals_err = ctx
        .consensus
        .validate_mempool_transaction(&mut bad_decimals_mtx, &TransactionValidationArgs::default())
        .expect_err("liquidity assets must reject non-zero decimals");
    assert!(
        format!("{bad_decimals_err:?}").contains("liquidity asset decimals must be `0`"),
        "unexpected liquidity decimals error: {bad_decimals_err:?}"
    );

    let build_owner_tx = |payload| -> Transaction {
        payload_tx(
            vec![TransactionInput::new(fixture.owner_anchor, p2sh_signature_script(), 0, 0)],
            vec![TransactionOutput::new(fixture.owner_anchor_value - fixture.tx_fee, fixture.owner_script.clone())],
            payload,
        )
    };

    let legacy_mint = build_owner_tx(payload_mint(0, 1, fixture.asset_id, fixture.owner_id, 1));
    let mut legacy_mint_mtx = MutableTransaction::from_tx(legacy_mint);
    let mint_err = ctx
        .consensus
        .validate_mempool_transaction(&mut legacy_mint_mtx, &TransactionValidationArgs::default())
        .expect_err("liquidity token must not be mintable through the legacy mint op");
    assert!(
        format!("{mint_err:?}").contains("legacy mint is invalid for liquidity asset"),
        "unexpected liquidity mint error: {mint_err:?}"
    );

    let legacy_burn = build_owner_tx(payload_burn(0, 1, fixture.asset_id, 1));
    let mut legacy_burn_mtx = MutableTransaction::from_tx(legacy_burn);
    let burn_err = ctx
        .consensus
        .validate_mempool_transaction(&mut legacy_burn_mtx, &TransactionValidationArgs::default())
        .expect_err("liquidity token must not be burnable through the legacy burn op");
    assert!(
        format!("{burn_err:?}").contains("legacy burn is invalid for liquidity asset"),
        "unexpected liquidity burn error: {burn_err:?}"
    );

    let transfer = build_owner_tx(payload_transfer(0, 1, fixture.asset_id, fixture.second_owner_id, 1));
    let mut transfer_mtx = MutableTransaction::from_tx(transfer);
    ctx.consensus
        .validate_mempool_transaction(&mut transfer_mtx, &TransactionValidationArgs::default())
        .expect("holders should be able to transfer liquidity tokens normally");

    let atomic_after = ctx.consensus.virtual_atomic_state();
    assert_eq!(atomic_after.canonical_hash(), root_before);
    assert_eq!(balance_of(&atomic_after, fixture.asset_id, fixture.owner_id), fixture.launch_token_out);
    assert_eq!(balance_of(&atomic_after, fixture.asset_id, fixture.second_owner_id), 0);
}

#[tokio::test]
async fn atomic_same_owner_nonce_conflict_in_parallel_blocks_applies_once() {
    let mut ctx = liquidity_test_context();
    let owner_script = cryptix_txscript::pay_to_script_hash_script(&p2sh_redeem_script());
    let owner_id = atomic_owner_id_from_script(&owner_script).expect("owner id should derive from P2SH");
    ctx.miner_data = MinerData::new(owner_script.clone(), vec![]);

    for _ in 0..4 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await;
    }
    let utxos = find_virtual_utxos_by_script(&ctx, &owner_script, 2);
    let tx_fee = 10_000u64;
    let parent = ctx.consensus.get_sink();

    let create_a = payload_tx(
        vec![TransactionInput::new(utxos[0].0, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(utxos[0].1.amount - tx_fee, owner_script.clone())],
        payload_create_asset(0, 1, owner_id, b"RaceA", b"RACA"),
    );
    let asset_a = create_a.id().as_bytes();
    let create_b = payload_tx(
        vec![TransactionInput::new(utxos[1].0, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(utxos[1].1.amount - tx_fee, owner_script.clone())],
        payload_create_asset(0, 1, owner_id, b"RaceB", b"RACB"),
    );
    let asset_b = create_b.id().as_bytes();

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let block_a = ctx.build_utxo_valid_block_with_parents_and_transactions(vec![parent], vec![create_a], 40, ctx.simulated_time);
    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let block_b = ctx.build_utxo_valid_block_with_parents_and_transactions(vec![parent], vec![create_b], 41, ctx.simulated_time);

    ctx.validate_and_insert_block(block_a.to_immutable()).await;
    ctx.validate_and_insert_block(block_b.to_immutable()).await;

    let atomic = ctx.consensus.virtual_atomic_state();
    let applied_assets = [asset_a, asset_b].into_iter().filter(|asset_id| atomic.assets.contains_key(asset_id)).count();
    assert_eq!(applied_assets, 1);
    assert_eq!(atomic.next_nonces.get(&AtomicNonceKey::owner(owner_id)), Some(&2));
}

#[tokio::test]
async fn atomic_duplicate_txid_in_parallel_blocks_is_accepted_once() {
    let mut ctx = liquidity_test_context();
    let owner_script = cryptix_txscript::pay_to_script_hash_script(&p2sh_redeem_script());
    let owner_id = atomic_owner_id_from_script(&owner_script).expect("owner id should derive from P2SH");
    ctx.miner_data = MinerData::new(owner_script.clone(), vec![]);

    for _ in 0..4 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await;
    }
    let utxos = find_virtual_utxos_by_script(&ctx, &owner_script, 1);
    let tx_fee = 10_000u64;
    let parent = ctx.consensus.get_sink();

    let create = payload_tx(
        vec![TransactionInput::new(utxos[0].0, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(utxos[0].1.amount - tx_fee, owner_script.clone())],
        payload_create_asset(0, 1, owner_id, b"DupTx", b"DUP"),
    );
    let txid = create.id();
    let asset_id = txid.as_bytes();

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let block_a = ctx.build_utxo_valid_block_with_parents_and_transactions(vec![parent], vec![create.clone()], 46, ctx.simulated_time);
    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let block_b = ctx.build_utxo_valid_block_with_parents_and_transactions(vec![parent], vec![create], 47, ctx.simulated_time);

    ctx.validate_and_insert_block(block_a.to_immutable()).await;
    ctx.validate_and_insert_block(block_b.to_immutable()).await;

    let atomic = ctx.consensus.virtual_atomic_state();
    assert!(atomic.assets.contains_key(&asset_id));
    assert_eq!(atomic.next_nonces.get(&AtomicNonceKey::owner(owner_id)), Some(&2));

    let acceptance_data =
        ctx.consensus.get_block_acceptance_data(ctx.consensus.get_sink()).expect("sink acceptance data should exist");
    let duplicate_accepts = acceptance_data
        .iter()
        .flat_map(|block_acceptance| block_acceptance.accepted_transactions.iter())
        .filter(|accepted| accepted.transaction_id == txid)
        .count();
    assert!(
        duplicate_accepts <= 1,
        "same txid must not be accepted twice in one virtual mergeset; observed {duplicate_accepts} acceptance entries"
    );
}

#[tokio::test]
async fn atomic_block_template_rejects_duplicate_txid_before_atomic_state() {
    let mut ctx = liquidity_test_context();
    let owner_script = cryptix_txscript::pay_to_script_hash_script(&p2sh_redeem_script());
    let owner_id = atomic_owner_id_from_script(&owner_script).expect("owner id should derive from P2SH");
    ctx.miner_data = MinerData::new(owner_script.clone(), vec![]);

    for _ in 0..4 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await;
    }
    let utxos = find_virtual_utxos_by_script(&ctx, &owner_script, 1);
    let tx_fee = 10_000u64;
    let create = payload_tx(
        vec![TransactionInput::new(utxos[0].0, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(utxos[0].1.amount - tx_fee, owner_script)],
        payload_create_asset(0, 1, owner_id, b"DupTemplate", b"DPT"),
    );

    let result = ctx.consensus.build_block_template(
        ctx.miner_data.clone(),
        Box::new(OnetimeTxSelector::new(vec![create.clone(), create.clone()])),
        TemplateBuildMode::Standard,
    );
    assert!(result.is_err(), "duplicate txid must not be allowed into a block template");
    assert!(!ctx.consensus.virtual_atomic_state().assets.contains_key(&create.id().as_bytes()));
}

#[tokio::test]
async fn atomic_mempool_batch_rejects_duplicate_txid_before_atomic_state() {
    let mut ctx = liquidity_test_context();
    let owner_script = cryptix_txscript::pay_to_script_hash_script(&p2sh_redeem_script());
    let owner_id = atomic_owner_id_from_script(&owner_script).expect("owner id should derive from P2SH");
    ctx.miner_data = MinerData::new(owner_script.clone(), vec![]);

    for _ in 0..4 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await;
    }
    let utxos = find_virtual_utxos_by_script(&ctx, &owner_script, 1);
    let tx_fee = 10_000u64;
    let create = payload_tx(
        vec![TransactionInput::new(utxos[0].0, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(utxos[0].1.amount - tx_fee, owner_script)],
        payload_create_asset(0, 1, owner_id, b"DupBatch", b"DPB"),
    );

    let mut batch = vec![
        MutableTransaction::with_entries(Arc::new(create.clone()), vec![utxos[0].1.clone()]),
        MutableTransaction::with_entries(Arc::new(create.clone()), vec![utxos[0].1.clone()]),
    ];
    let results = ctx.consensus.validate_mempool_transactions_in_parallel(&mut batch, &TransactionValidationBatchArgs::default());

    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1, "one duplicate txid instance may validate: {results:?}");
    assert_eq!(
        results.iter().filter(|result| result.is_err()).count(),
        1,
        "one duplicate txid instance must be rejected before Atomic state: {results:?}"
    );
    assert!(
        format!("{:?}", results[1]).contains("duplicate transaction in mempool validation batch"),
        "duplicate batch rejection should be explicit: {results:?}"
    );
    assert!(!ctx.consensus.virtual_atomic_state().assets.contains_key(&create.id().as_bytes()));
}

#[tokio::test]
async fn atomic_mempool_batch_rejects_same_utxo_double_spend_before_atomic_state() {
    let mut ctx = liquidity_test_context();
    let owner_script = cryptix_txscript::pay_to_script_hash_script(&p2sh_redeem_script());
    let owner_id = atomic_owner_id_from_script(&owner_script).expect("owner id should derive from P2SH");
    ctx.miner_data = MinerData::new(owner_script.clone(), vec![]);

    for _ in 0..4 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await;
    }
    let utxos = find_virtual_utxos_by_script(&ctx, &owner_script, 1);
    let tx_fee = 10_000u64;
    let first = payload_tx(
        vec![TransactionInput::new(utxos[0].0, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(utxos[0].1.amount - tx_fee, owner_script.clone())],
        payload_create_asset(0, 1, owner_id, b"DoubleSpendA", b"DSA"),
    );
    let second = payload_tx(
        vec![TransactionInput::new(utxos[0].0, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(utxos[0].1.amount - tx_fee, owner_script)],
        payload_create_asset(0, 2, owner_id, b"DoubleSpendB", b"DSB"),
    );

    let first_asset = first.id().as_bytes();
    let second_asset = second.id().as_bytes();
    let mut batch = vec![
        MutableTransaction::with_entries(Arc::new(first), vec![utxos[0].1.clone()]),
        MutableTransaction::with_entries(Arc::new(second), vec![utxos[0].1.clone()]),
    ];
    let results = ctx.consensus.validate_mempool_transactions_in_parallel(&mut batch, &TransactionValidationBatchArgs::default());

    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1, "one same-UTXO candidate may validate: {results:?}");
    assert_eq!(
        results.iter().filter(|result| format!("{:?}", result).contains("MissingTxOutpoints")).count(),
        1,
        "one same-UTXO candidate must be rejected before Atomic state: {results:?}"
    );
    let atomic = ctx.consensus.virtual_atomic_state();
    assert!(!atomic.assets.contains_key(&first_asset));
    assert!(!atomic.assets.contains_key(&second_asset));
}

#[tokio::test]
async fn atomic_nonce_conflict_reorg_prefers_selected_branch_state() {
    let mut ctx = liquidity_test_context();
    let owner_script = cryptix_txscript::pay_to_script_hash_script(&p2sh_redeem_script());
    let owner_id = atomic_owner_id_from_script(&owner_script).expect("owner id should derive from P2SH");
    ctx.miner_data = MinerData::new(owner_script.clone(), vec![]);

    for _ in 0..4 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await;
    }
    let utxos = find_virtual_utxos_by_script(&ctx, &owner_script, 2);
    let tx_fee = 10_000u64;
    let parent = ctx.consensus.get_sink();

    let create_a = payload_tx(
        vec![TransactionInput::new(utxos[0].0, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(utxos[0].1.amount - tx_fee, owner_script.clone())],
        payload_create_asset(0, 1, owner_id, b"ForkA", b"FKA"),
    );
    let asset_a = create_a.id().as_bytes();
    let create_b = payload_tx(
        vec![TransactionInput::new(utxos[1].0, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(utxos[1].1.amount - tx_fee, owner_script.clone())],
        payload_create_asset(0, 1, owner_id, b"ForkB", b"FKB"),
    );
    let asset_b = create_b.id().as_bytes();

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let block_a = ctx.build_utxo_valid_block_with_parents_and_transactions(vec![parent], vec![create_a], 43, ctx.simulated_time);
    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let block_b = ctx.build_utxo_valid_block_with_parents_and_transactions(vec![parent], vec![create_b], 44, ctx.simulated_time);
    let block_b_hash = block_b.header.hash;

    ctx.validate_and_insert_block(block_a.to_immutable()).await;
    ctx.validate_and_insert_block(block_b.to_immutable()).await;

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let block_b_child = ctx.build_utxo_valid_block_with_parents_and_transactions(vec![block_b_hash], vec![], 45, ctx.simulated_time);
    ctx.validate_and_insert_block(block_b_child.to_immutable()).await;

    let atomic = ctx.consensus.virtual_atomic_state();
    assert!(!atomic.assets.contains_key(&asset_a), "stale nonce branch asset must be removed after selected-branch reorg");
    assert!(atomic.assets.contains_key(&asset_b), "selected branch asset must define the atomic state after reorg");
    assert_eq!(atomic.next_nonces.get(&AtomicNonceKey::owner(owner_id)), Some(&2));
}

#[tokio::test]
async fn atomic_reorg_removes_losing_branch_state_and_accepts_new_atomic_block() {
    let mut ctx = liquidity_test_context();
    let owner_script = cryptix_txscript::pay_to_script_hash_script(&p2sh_redeem_script());
    let receiver_script = cryptix_txscript::pay_to_script_hash_script(&second_p2sh_redeem_script());
    let owner_id = atomic_owner_id_from_script(&owner_script).expect("owner id should derive from P2SH");
    let receiver_id = atomic_owner_id_from_script(&receiver_script).expect("receiver id should derive from P2SH");
    ctx.miner_data = MinerData::new(owner_script.clone(), vec![]);

    for _ in 0..6 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await;
    }
    let utxos = find_virtual_utxos_by_script(&ctx, &owner_script, 4);
    let tx_fee = 10_000u64;
    let fork_parent = ctx.consensus.get_sink();

    let create_old_branch = payload_tx(
        vec![TransactionInput::new(utxos[0].0, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(utxos[0].1.amount - tx_fee, owner_script.clone())],
        payload_create_asset_with_mint(0, 1, owner_id, b"OldBranch", b"OLD", 1_000, owner_id),
    );
    let old_branch_asset = create_old_branch.id().as_bytes();
    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let old_branch = ctx.build_utxo_valid_block_with_parents_and_transactions(
        vec![fork_parent],
        vec![create_old_branch],
        6_101,
        ctx.simulated_time,
    );
    let old_branch_hash = old_branch.header.hash;
    ctx.validate_and_insert_utxo_valid_block(old_branch.to_immutable()).await;

    let transfer_from_old_branch_asset = payload_tx(
        vec![TransactionInput::new(utxos[1].0, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(utxos[1].1.amount - tx_fee, owner_script.clone())],
        payload_transfer(0, 1, old_branch_asset, receiver_id, 100),
    );
    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let local_child = ctx.build_utxo_valid_block_with_parents_and_transactions(
        vec![old_branch_hash],
        vec![transfer_from_old_branch_asset],
        6_102,
        ctx.simulated_time,
    );
    ctx.validate_and_insert_utxo_valid_block(local_child.to_immutable()).await;

    let atomic_before_reorg = ctx.consensus.virtual_atomic_state();
    assert!(atomic_before_reorg.assets.contains_key(&old_branch_asset));
    assert_eq!(balance_of(&atomic_before_reorg, old_branch_asset, owner_id), 900);
    assert_eq!(balance_of(&atomic_before_reorg, old_branch_asset, receiver_id), 100);
    assert_eq!(atomic_before_reorg.next_nonces.get(&AtomicNonceKey::owner(owner_id)), Some(&2));
    assert_eq!(atomic_before_reorg.next_nonces.get(&AtomicNonceKey::asset(owner_id, old_branch_asset)), Some(&2));

    let create_winning_branch = payload_tx(
        vec![TransactionInput::new(utxos[2].0, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(utxos[2].1.amount - tx_fee, owner_script.clone())],
        payload_create_asset_with_mint(0, 1, owner_id, b"Winner", b"WIN", 1_000, owner_id),
    );
    let winning_branch_asset = create_winning_branch.id().as_bytes();
    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let winning_branch = ctx.build_utxo_valid_block_with_parents_and_transactions(
        vec![fork_parent],
        vec![create_winning_branch],
        6_201,
        ctx.simulated_time,
    );
    let mut winning_tip = winning_branch.header.hash;
    ctx.validate_and_insert_block(winning_branch.to_immutable()).await;

    for nonce in 6_202..6_206 {
        ctx.simulated_time += ctx.consensus.params().target_time_per_block;
        let extension = ctx.build_utxo_valid_block_with_parents_and_transactions(vec![winning_tip], vec![], nonce, ctx.simulated_time);
        winning_tip = extension.header.hash;
        ctx.validate_and_insert_block(extension.to_immutable()).await;
    }
    assert!(ctx.consensus.reachability_service().is_chain_ancestor_of(winning_tip, ctx.consensus.get_sink()));

    let atomic_after_reorg = ctx.consensus.virtual_atomic_state();
    assert!(
        !atomic_after_reorg.assets.contains_key(&old_branch_asset),
        "Atomic asset from the losing branch must not remain in virtual state after reorg"
    );
    assert_eq!(balance_of(&atomic_after_reorg, old_branch_asset, owner_id), 0);
    assert_eq!(balance_of(&atomic_after_reorg, old_branch_asset, receiver_id), 0);
    assert!(!atomic_after_reorg.next_nonces.contains_key(&AtomicNonceKey::asset(owner_id, old_branch_asset)));
    assert!(
        atomic_after_reorg.assets.contains_key(&winning_branch_asset),
        "Atomic asset from the selected winning branch must be present after reorg"
    );
    assert_eq!(balance_of(&atomic_after_reorg, winning_branch_asset, owner_id), 1_000);
    assert_eq!(atomic_after_reorg.next_nonces.get(&AtomicNonceKey::owner(owner_id)), Some(&2));

    let post_reorg_utxos = find_virtual_utxos_by_script(&ctx, &owner_script, 3);
    let stale_create_after_reorg = payload_tx(
        vec![TransactionInput::new(post_reorg_utxos[0].0, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(post_reorg_utxos[0].1.amount - tx_fee, owner_script.clone())],
        payload_create_asset(0, 1, owner_id, b"StaleAfterReorg", b"STA"),
    );
    let stale_transfer_from_removed_asset = payload_tx(
        vec![TransactionInput::new(post_reorg_utxos[1].0, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(post_reorg_utxos[1].1.amount - tx_fee, owner_script.clone())],
        payload_transfer(0, 1, old_branch_asset, receiver_id, 1),
    );
    let create_after_reorg = payload_tx(
        vec![TransactionInput::new(post_reorg_utxos[2].0, p2sh_signature_script(), 0, 0)],
        vec![TransactionOutput::new(post_reorg_utxos[2].1.amount - tx_fee, owner_script.clone())],
        payload_create_asset(0, 2, owner_id, b"AfterReorg", b"AFT"),
    );
    let after_reorg_asset = create_after_reorg.id().as_bytes();

    let mut reorg_mempool_batch = vec![
        MutableTransaction::with_entries(Arc::new(stale_create_after_reorg), vec![post_reorg_utxos[0].1.clone()]),
        MutableTransaction::with_entries(Arc::new(stale_transfer_from_removed_asset), vec![post_reorg_utxos[1].1.clone()]),
        MutableTransaction::with_entries(Arc::new(create_after_reorg.clone()), vec![post_reorg_utxos[2].1.clone()]),
    ];
    let reorg_mempool_results =
        ctx.consensus.validate_mempool_transactions_in_parallel(&mut reorg_mempool_batch, &TransactionValidationBatchArgs::default());
    assert!(reorg_mempool_results[0].is_err(), "stale owner nonce from losing branch must be rejected after reorg");
    assert!(reorg_mempool_results[1].is_err(), "transfer referencing an asset removed by reorg must be rejected after reorg");
    assert!(
        reorg_mempool_results[2].is_ok(),
        "fresh nonce on the winning branch must remain valid after rejecting stale reorg transactions: {reorg_mempool_results:?}"
    );
    assert!(
        !ctx.consensus.virtual_atomic_state().assets.contains_key(&after_reorg_asset),
        "mempool validation must not mutate virtual Atomic state"
    );

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let after_reorg = ctx.build_utxo_valid_block_with_parents_and_transactions(
        vec![ctx.consensus.get_sink()],
        vec![create_after_reorg],
        6_301,
        ctx.simulated_time,
    );
    ctx.validate_and_insert_utxo_valid_block(after_reorg.to_immutable()).await;

    let atomic_final = ctx.consensus.virtual_atomic_state();
    assert!(!atomic_final.assets.contains_key(&old_branch_asset));
    assert_eq!(balance_of(&atomic_final, old_branch_asset, owner_id), 0);
    assert_eq!(balance_of(&atomic_final, old_branch_asset, receiver_id), 0);
    assert!(!atomic_final.next_nonces.contains_key(&AtomicNonceKey::asset(owner_id, old_branch_asset)));
    assert!(atomic_final.assets.contains_key(&winning_branch_asset));
    assert_eq!(balance_of(&atomic_final, winning_branch_asset, owner_id), 1_000);
    assert!(atomic_final.assets.contains_key(&after_reorg_asset));
    assert_eq!(atomic_final.next_nonces.get(&AtomicNonceKey::owner(owner_id)), Some(&3));
}

#[tokio::test]
async fn liquidity_different_pools_can_advance_in_same_block() {
    let mut ctx = liquidity_test_context();
    let owner_redeem_script = p2sh_redeem_script();
    let owner_script = cryptix_txscript::pay_to_script_hash_script(&owner_redeem_script);
    let recipient_payload = owner_script.script()[2..34].to_vec();
    let owner_id = atomic_owner_id_from_script(&owner_script).expect("owner id should derive from P2SH");
    ctx.miner_data = MinerData::new(owner_script.clone(), vec![]);

    for _ in 0..6 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await;
    }
    let utxos = find_virtual_utxos_by_script(&ctx, &owner_script, 4);
    let max_supply = 1_000_000u128;
    let seed_reserve = SOMPI_PER_CRYPTIX;
    let fee_bps = 100u16;
    let launch_buy_budget = 10 * SOMPI_PER_CRYPTIX;
    let tx_fee = 10_000u64;
    let (launch_buy, launch_token_out) = canonical_buy_from_budget(
        max_supply,
        INITIAL_LIQUIDITY_VIRTUAL_CPAY_RESERVES_SOMPI,
        initial_liquidity_virtual_token_reserves(max_supply),
        launch_buy_budget,
        fee_bps,
    );
    let create_vault_value = seed_reserve + launch_buy;

    let create_a_change = utxos[0].1.amount - create_vault_value - tx_fee;
    let create_a = payload_tx(
        vec![TransactionInput::new(utxos[0].0, p2sh_signature_script_for(&owner_redeem_script), 0, 0)],
        vec![
            TransactionOutput::new(create_vault_value, liquidity_vault_script()),
            TransactionOutput::new(create_a_change, owner_script.clone()),
        ],
        payload_create_liquidity(0, 1, max_supply, seed_reserve, fee_bps, &recipient_payload, launch_buy, 1),
    );
    let asset_a = create_a.id().as_bytes();
    let create_b_change = utxos[1].1.amount - create_vault_value - tx_fee;
    let create_b = payload_tx(
        vec![TransactionInput::new(utxos[1].0, p2sh_signature_script_for(&owner_redeem_script), 0, 0)],
        vec![
            TransactionOutput::new(create_vault_value, liquidity_vault_script()),
            TransactionOutput::new(create_b_change, owner_script.clone()),
        ],
        payload_create_liquidity(0, 2, max_supply, seed_reserve, fee_bps, &recipient_payload, launch_buy, 1),
    );
    let asset_b = create_b.id().as_bytes();

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let create_template = ctx.build_block_template_with_transactions(vec![create_a, create_b], 50, ctx.simulated_time);
    ctx.validate_and_insert_block(create_template.block.to_immutable()).await;

    let atomic = ctx.consensus.virtual_atomic_state();
    let pool_a = atomic.assets.get(&asset_a).and_then(|asset| asset.liquidity.as_ref()).expect("pool A should exist").clone();
    let pool_b = atomic.assets.get(&asset_b).and_then(|asset| asset.liquidity.as_ref()).expect("pool B should exist").clone();
    assert_eq!(pool_a.pool_nonce, 1);
    assert_eq!(pool_b.pool_nonce, 1);

    let (buy_a, token_out_a, _) = build_liquidity_buy_tx(
        asset_a,
        &pool_a,
        TransactionOutpoint::new(Hash::from_bytes(asset_a), 1),
        create_a_change,
        &owner_script,
        p2sh_signature_script_for(&owner_redeem_script),
        1,
        10 * SOMPI_PER_CRYPTIX,
        tx_fee,
    );
    let (buy_b, token_out_b, _) = build_liquidity_buy_tx(
        asset_b,
        &pool_b,
        TransactionOutpoint::new(Hash::from_bytes(asset_b), 1),
        create_b_change,
        &owner_script,
        p2sh_signature_script_for(&owner_redeem_script),
        1,
        20 * SOMPI_PER_CRYPTIX,
        tx_fee,
    );

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let buy_template = ctx.build_block_template_with_transactions(vec![buy_a, buy_b], 51, ctx.simulated_time);
    ctx.validate_and_insert_block(buy_template.block.to_immutable()).await;

    let atomic = ctx.consensus.virtual_atomic_state();
    let pool_a = atomic.assets.get(&asset_a).and_then(|asset| asset.liquidity.as_ref()).expect("pool A should exist");
    let pool_b = atomic.assets.get(&asset_b).and_then(|asset| asset.liquidity.as_ref()).expect("pool B should exist");
    assert_eq!(pool_a.pool_nonce, 2);
    assert_eq!(pool_b.pool_nonce, 2);
    assert_eq!(balance_of(&atomic, asset_a, owner_id), launch_token_out + token_out_a);
    assert_eq!(balance_of(&atomic, asset_b, owner_id), launch_token_out + token_out_b);
    assert_eq!(atomic.next_nonces.get(&AtomicNonceKey::asset(owner_id, asset_a)), Some(&2));
    assert_eq!(atomic.next_nonces.get(&AtomicNonceKey::asset(owner_id, asset_b)), Some(&2));
}

#[tokio::test]
async fn batch_mempool_validation_orders_same_pool_by_pool_nonce_across_owners() {
    let (ctx, fixture) = setup_dual_owner_liquidity_pool().await;
    let owner_redeem_script = p2sh_redeem_script();
    let second_owner_redeem_script = second_p2sh_redeem_script();
    let tx_fee = fixture.tx_fee;

    let (buy_1, token_out_1, vault_value_1) = build_liquidity_buy_tx(
        fixture.asset_id,
        &fixture.pool,
        fixture.owner_anchor,
        fixture.owner_anchor_value,
        &fixture.owner_script,
        p2sh_signature_script_for(&owner_redeem_script),
        1,
        10 * SOMPI_PER_CRYPTIX,
        tx_fee,
    );

    let buy_in_1 = vault_value_1 - fixture.pool.vault_value_sompi;
    let trade_fee_1 = fee(buy_in_1, fixture.pool.fee_bps);
    let net_in_1 = buy_in_1 - trade_fee_1;
    let mut pool_after_buy_1 = fixture.pool.clone();
    pool_after_buy_1.real_cpay_reserves_sompi += net_in_1;
    pool_after_buy_1.real_token_reserves -= token_out_1;
    pool_after_buy_1.virtual_cpay_reserves_sompi += net_in_1;
    pool_after_buy_1.virtual_token_reserves -= token_out_1;
    pool_after_buy_1.vault_value_sompi = vault_value_1;
    pool_after_buy_1.vault_outpoint = TransactionOutpoint::new(buy_1.id(), 0);
    pool_after_buy_1.pool_nonce += 1;
    pool_after_buy_1.unclaimed_fee_total_sompi += trade_fee_1;
    pool_after_buy_1.fee_recipients[0].unclaimed_sompi += trade_fee_1;

    let (buy_2, _, _) = build_liquidity_buy_tx(
        fixture.asset_id,
        &pool_after_buy_1,
        fixture.second_owner_anchor,
        fixture.second_owner_anchor_value,
        &fixture.second_owner_script,
        p2sh_signature_script_for(&second_owner_redeem_script),
        1,
        20 * SOMPI_PER_CRYPTIX,
        tx_fee,
    );

    let initial_vault_entry = UtxoEntry::new(fixture.pool.vault_value_sompi, liquidity_vault_script(), UNACCEPTED_DAA_SCORE, false);
    let pending_vault_entry = UtxoEntry::new(vault_value_1, liquidity_vault_script(), UNACCEPTED_DAA_SCORE, false);
    let owner_anchor_entry = UtxoEntry::new(fixture.owner_anchor_value, fixture.owner_script.clone(), UNACCEPTED_DAA_SCORE, false);
    let second_owner_anchor_entry =
        UtxoEntry::new(fixture.second_owner_anchor_value, fixture.second_owner_script.clone(), UNACCEPTED_DAA_SCORE, false);

    let mut batch = vec![
        MutableTransaction::with_entries(Arc::new(buy_2), vec![pending_vault_entry, second_owner_anchor_entry]),
        MutableTransaction::with_entries(Arc::new(buy_1), vec![initial_vault_entry, owner_anchor_entry]),
    ];
    let results = ctx.consensus.validate_mempool_transactions_in_parallel(&mut batch, &TransactionValidationBatchArgs::default());

    assert!(results.iter().all(Result::is_ok), "same-pool nonce chain should validate even when submitted out of order: {results:?}");
}

#[tokio::test]
async fn batch_mempool_validation_rejects_duplicate_liquidity_pool_nonce_across_owners() {
    let (ctx, fixture) = setup_dual_owner_liquidity_pool().await;
    let owner_redeem_script = p2sh_redeem_script();
    let second_owner_redeem_script = second_p2sh_redeem_script();

    let (owner_buy_tx, _, _) = build_liquidity_buy_tx(
        fixture.asset_id,
        &fixture.pool,
        fixture.owner_anchor,
        fixture.owner_anchor_value,
        &fixture.owner_script,
        p2sh_signature_script_for(&owner_redeem_script),
        1,
        10 * SOMPI_PER_CRYPTIX,
        fixture.tx_fee,
    );
    let (second_owner_buy_tx, _, _) = build_liquidity_buy_tx(
        fixture.asset_id,
        &fixture.pool,
        fixture.second_owner_anchor,
        fixture.second_owner_anchor_value,
        &fixture.second_owner_script,
        p2sh_signature_script_for(&second_owner_redeem_script),
        1,
        20 * SOMPI_PER_CRYPTIX,
        fixture.tx_fee,
    );

    let initial_vault_entry = UtxoEntry::new(fixture.pool.vault_value_sompi, liquidity_vault_script(), UNACCEPTED_DAA_SCORE, false);
    let owner_anchor_entry = UtxoEntry::new(fixture.owner_anchor_value, fixture.owner_script.clone(), UNACCEPTED_DAA_SCORE, false);
    let second_owner_anchor_entry =
        UtxoEntry::new(fixture.second_owner_anchor_value, fixture.second_owner_script.clone(), UNACCEPTED_DAA_SCORE, false);

    let mut batch = vec![
        MutableTransaction::with_entries(Arc::new(second_owner_buy_tx), vec![initial_vault_entry.clone(), second_owner_anchor_entry]),
        MutableTransaction::with_entries(Arc::new(owner_buy_tx), vec![initial_vault_entry, owner_anchor_entry]),
    ];
    let results = ctx.consensus.validate_mempool_transactions_in_parallel(&mut batch, &TransactionValidationBatchArgs::default());

    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1, "exactly one duplicate pool-nonce tx may pass: {results:?}");
    assert_eq!(
        results.iter().filter(|result| result.is_err()).count(),
        1,
        "exactly one duplicate pool-nonce tx must fail: {results:?}"
    );
    assert!(
        results.iter().filter_map(|result| result.as_ref().err()).any(|err| {
            let text = format!("{err:?}");
            text.contains("stale liquidity nonce")
                || text.contains("unknown LiquidityVault input outpoint")
                || text.contains("MissingTxOutpoints")
        }),
        "duplicate pool nonce should be rejected after the first accepted transition advances the pool head: {results:?}"
    );
}

#[tokio::test]
async fn batch_mempool_validation_rejects_liquidity_pool_nonce_gap() {
    let (ctx, fixture) = setup_dual_owner_liquidity_pool().await;
    let owner_redeem_script = p2sh_redeem_script();
    let mut future_pool = fixture.pool.clone();
    future_pool.pool_nonce += 1;

    let (future_nonce_buy_tx, _, _) = build_liquidity_buy_tx(
        fixture.asset_id,
        &future_pool,
        fixture.owner_anchor,
        fixture.owner_anchor_value,
        &fixture.owner_script,
        p2sh_signature_script_for(&owner_redeem_script),
        1,
        10 * SOMPI_PER_CRYPTIX,
        fixture.tx_fee,
    );

    let initial_vault_entry = UtxoEntry::new(fixture.pool.vault_value_sompi, liquidity_vault_script(), UNACCEPTED_DAA_SCORE, false);
    let owner_anchor_entry = UtxoEntry::new(fixture.owner_anchor_value, fixture.owner_script.clone(), UNACCEPTED_DAA_SCORE, false);

    let mut batch =
        vec![MutableTransaction::with_entries(Arc::new(future_nonce_buy_tx), vec![initial_vault_entry, owner_anchor_entry])];
    let results = ctx.consensus.validate_mempool_transactions_in_parallel(&mut batch, &TransactionValidationBatchArgs::default());

    assert_eq!(results.len(), 1);
    let err = results.into_iter().next().unwrap().expect_err("future pool nonce must be rejected");
    assert!(format!("{err:?}").contains("stale liquidity nonce"), "unexpected future pool nonce validation error: {err:?}");
}

#[tokio::test]
async fn batch_mempool_validation_rejects_non_cat_liquidity_vault_outputs() {
    let mut ctx = liquidity_test_context();
    let owner_script = cryptix_txscript::pay_to_script_hash_script(&p2sh_redeem_script());
    ctx.miner_data = MinerData::new(owner_script.clone(), vec![]);

    for _ in 0..3 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await;
    }
    let (funding_outpoint, funding_entry) = find_virtual_utxo_by_script(&ctx, &owner_script);

    let vault_value = 1_000u64;
    let tx_fee = 10_000u64;
    let mut invalid_tx = Transaction::new(
        TX_VERSION,
        vec![TransactionInput::new(funding_outpoint, p2sh_signature_script(), 0, 0)],
        vec![
            TransactionOutput::new(vault_value, liquidity_vault_script()),
            TransactionOutput::new(funding_entry.amount - vault_value - tx_fee, owner_script),
        ],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );
    invalid_tx.finalize();
    let mut batch = vec![MutableTransaction::from_tx(invalid_tx)];
    let results = ctx.consensus.validate_mempool_transactions_in_parallel(&mut batch, &TransactionValidationBatchArgs::default());

    assert_eq!(results.len(), 1);
    let err = results.into_iter().next().unwrap().expect_err("non-CAT LiquidityVault output must be rejected");
    assert!(
        format!("{err:?}").contains("reserved LiquidityVault scripts require a CAT liquidity payload"),
        "unexpected batch validation error: {err:?}"
    );
}

#[tokio::test]
async fn liquidity_consensus_e2e_create_buy_sell_claim_updates_vault_state() {
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.coinbase_maturity = 0;
            p.payload_hf_activation_daa_score = 0;
        })
        .build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let owner_script = cryptix_txscript::pay_to_script_hash_script(&p2sh_redeem_script());
    let recipient_payload = owner_script.script()[2..34].to_vec();
    let owner_id = atomic_owner_id_from_script(&owner_script).expect("owner id should derive from P2SH");
    ctx.miner_data = MinerData::new(owner_script.clone(), vec![]);

    for _ in 0..3 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await;
    }
    let (funding_outpoint, funding_entry) = find_virtual_utxo_by_script(&ctx, &owner_script);

    let max_supply = 1_000_000u128;
    let seed_reserve = SOMPI_PER_CRYPTIX;
    let fee_bps = 100u16;
    let launch_buy_budget = 10 * SOMPI_PER_CRYPTIX;
    let tx_fee = 10_000u64;
    let (launch_buy, launch_token_out) = canonical_buy_from_budget(
        max_supply,
        INITIAL_LIQUIDITY_VIRTUAL_CPAY_RESERVES_SOMPI,
        initial_liquidity_virtual_token_reserves(max_supply),
        launch_buy_budget,
        fee_bps,
    );
    let create_vault_value = seed_reserve + launch_buy;
    let create_change_value = funding_entry.amount - create_vault_value - tx_fee;
    let create_payload = payload_create_liquidity(0, 1, max_supply, seed_reserve, fee_bps, &recipient_payload, launch_buy, 1);
    let create_tx = payload_tx(
        vec![TransactionInput::new(funding_outpoint, p2sh_signature_script(), 0, 0)],
        vec![
            TransactionOutput::new(create_vault_value, liquidity_vault_script()),
            TransactionOutput::new(create_change_value, owner_script.clone()),
        ],
        create_payload,
    );
    let asset_id = create_tx.id().as_bytes();
    let mut owner_anchor = TransactionOutpoint::new(create_tx.id(), 1);
    let mut owner_anchor_value = create_change_value;
    let mut create_mtx = MutableTransaction::from_tx(create_tx.clone());
    ctx.consensus
        .validate_mempool_transaction(&mut create_mtx, &TransactionValidationArgs::default())
        .expect("create-liquidity tx should validate");

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let create_template = ctx.build_block_template_with_transactions(vec![create_tx], 10, ctx.simulated_time);
    ctx.validate_and_insert_block(create_template.block.to_immutable()).await;
    let atomic = ctx.consensus.virtual_atomic_state();
    let asset = atomic.assets.get(&asset_id).expect("liquidity asset should exist");
    assert_eq!(asset.asset_class, AtomicAssetClass::Liquidity);
    assert_eq!(atomic.balances.get(&AtomicBalanceKey { asset_id, owner_id }), Some(&launch_token_out));
    let pool = asset.liquidity.as_ref().expect("pool should exist");
    assert_eq!(pool.pool_nonce, 1);
    assert_eq!(pool.vault_value_sompi, create_vault_value);
    assert_eq!(pool.vault_value_sompi, pool.real_cpay_reserves_sompi + pool.unclaimed_fee_total_sompi);

    let buy_in_budget = 10 * SOMPI_PER_CRYPTIX;
    let overpay_buy_tx = payload_tx(
        vec![
            TransactionInput::new(pool.vault_outpoint, vec![], 0, 0),
            TransactionInput::new(owner_anchor, p2sh_signature_script(), 0, 0),
        ],
        vec![
            TransactionOutput::new(pool.vault_value_sompi + buy_in_budget, liquidity_vault_script()),
            TransactionOutput::new(owner_anchor_value - buy_in_budget - tx_fee, owner_script.clone()),
        ],
        payload_buy_liquidity(1, 1, asset_id, pool.pool_nonce, buy_in_budget, 1),
    );
    let mut overpay_mtx = MutableTransaction::from_tx(overpay_buy_tx);
    let err = ctx
        .consensus
        .validate_mempool_transaction(&mut overpay_mtx, &TransactionValidationArgs::default())
        .expect_err("overpaying buy should be rejected");
    assert!(format!("{err:?}").contains("buy CPAY input is not canonical"), "unexpected overpay validation error: {err:?}");

    let (buy_in, buy_token_out) = canonical_buy_from_budget(
        pool.real_token_reserves,
        pool.virtual_cpay_reserves_sompi,
        pool.virtual_token_reserves,
        buy_in_budget,
        fee_bps,
    );
    let buy_vault_value = pool.vault_value_sompi + buy_in;
    owner_anchor_value -= buy_in + tx_fee;
    let buy_payload = payload_buy_liquidity(1, 1, asset_id, pool.pool_nonce, buy_in, 1);
    let buy_tx = payload_tx(
        vec![
            TransactionInput::new(pool.vault_outpoint, vec![], 0, 0),
            TransactionInput::new(owner_anchor, p2sh_signature_script(), 0, 0),
        ],
        vec![
            TransactionOutput::new(buy_vault_value, liquidity_vault_script()),
            TransactionOutput::new(owner_anchor_value, owner_script.clone()),
        ],
        buy_payload,
    );
    owner_anchor = TransactionOutpoint::new(buy_tx.id(), 1);

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let buy_template = ctx.build_block_template_with_transactions(vec![buy_tx], 11, ctx.simulated_time);
    ctx.validate_and_insert_block(buy_template.block.to_immutable()).await;
    let atomic = ctx.consensus.virtual_atomic_state();
    let asset = atomic.assets.get(&asset_id).expect("liquidity asset should exist");
    let pool = asset.liquidity.as_ref().expect("pool should exist");
    assert_eq!(pool.pool_nonce, 2);
    assert_eq!(pool.vault_value_sompi, buy_vault_value);
    assert_eq!(pool.vault_value_sompi, pool.real_cpay_reserves_sompi + pool.unclaimed_fee_total_sompi);
    assert_eq!(atomic.balances.get(&AtomicBalanceKey { asset_id, owner_id }), Some(&(launch_token_out + buy_token_out)));

    let token_in = 2u128;
    let (_, cpay_out) = quote_sell(pool.virtual_cpay_reserves_sompi, pool.virtual_token_reserves, token_in, fee_bps);
    assert!(cpay_out > 0);
    let sell_vault_value = pool.vault_value_sompi - cpay_out;
    owner_anchor_value -= tx_fee;
    let sell_payload = payload_sell_liquidity(1, 2, asset_id, pool.pool_nonce, token_in, cpay_out, 1);
    let sell_tx = payload_tx(
        vec![
            TransactionInput::new(pool.vault_outpoint, vec![], 0, 0),
            TransactionInput::new(owner_anchor, p2sh_signature_script(), 0, 0),
        ],
        vec![
            TransactionOutput::new(sell_vault_value, liquidity_vault_script()),
            TransactionOutput::new(cpay_out, owner_script.clone()),
            TransactionOutput::new(owner_anchor_value, owner_script.clone()),
        ],
        sell_payload,
    );
    owner_anchor = TransactionOutpoint::new(sell_tx.id(), 2);

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let sell_template = ctx.build_block_template_with_transactions(vec![sell_tx], 12, ctx.simulated_time);
    ctx.validate_and_insert_block(sell_template.block.to_immutable()).await;
    let atomic = ctx.consensus.virtual_atomic_state();
    let asset = atomic.assets.get(&asset_id).expect("liquidity asset should exist");
    let pool = asset.liquidity.as_ref().expect("pool should exist");
    assert_eq!(pool.pool_nonce, 3);
    assert_eq!(pool.vault_value_sompi, sell_vault_value);
    assert_eq!(pool.vault_value_sompi, pool.real_cpay_reserves_sompi + pool.unclaimed_fee_total_sompi);
    assert_eq!(atomic.balances.get(&AtomicBalanceKey { asset_id, owner_id }), Some(&(launch_token_out + buy_token_out - token_in)));
    assert!(pool.unclaimed_fee_total_sompi >= 1);

    let claim_amount = 1u64;
    let claim_vault_value = pool.vault_value_sompi - claim_amount;
    let unclaimed_before = pool.fee_recipients[0].unclaimed_sompi;
    owner_anchor_value -= tx_fee;
    let claim_payload = payload_claim_liquidity(1, 3, asset_id, pool.pool_nonce, 0, claim_amount, 1);
    let claim_tx = payload_tx(
        vec![
            TransactionInput::new(pool.vault_outpoint, vec![], 0, 0),
            TransactionInput::new(owner_anchor, p2sh_signature_script(), 0, 0),
        ],
        vec![
            TransactionOutput::new(claim_vault_value, liquidity_vault_script()),
            TransactionOutput::new(claim_amount, owner_script.clone()),
            TransactionOutput::new(owner_anchor_value, owner_script.clone()),
        ],
        claim_payload,
    );

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let claim_template = ctx.build_block_template_with_transactions(vec![claim_tx], 13, ctx.simulated_time);
    ctx.validate_and_insert_block(claim_template.block.to_immutable()).await;
    let atomic = ctx.consensus.virtual_atomic_state();
    let asset = atomic.assets.get(&asset_id).expect("liquidity asset should exist");
    let pool = asset.liquidity.as_ref().expect("pool should exist");
    assert_eq!(pool.pool_nonce, 4);
    assert_eq!(pool.vault_value_sompi, claim_vault_value);
    assert_eq!(pool.fee_recipients[0].unclaimed_sompi, unclaimed_before - claim_amount);
}

#[tokio::test]
async fn liquidity_serial_buy_sell_pressure_preserves_vault_accounting_and_roots() {
    let (mut ctx, fixture) = setup_dual_owner_liquidity_pool().await;
    let owner_redeem_script = p2sh_redeem_script();
    let mut owner_anchor = fixture.owner_anchor;
    let mut owner_anchor_value = fixture.owner_anchor_value;
    let mut expected_balance = fixture.launch_token_out;

    for step in 0..20u64 {
        let atomic_before = ctx.consensus.virtual_atomic_state();
        let pool = atomic_before
            .assets
            .get(&fixture.asset_id)
            .and_then(|asset| asset.liquidity.as_ref())
            .expect("pool must exist before pressure step")
            .clone();
        let auth_nonce = step + 1;
        let tx = if step % 2 == 0 {
            let (buy_tx, token_out, vault_value) = build_liquidity_buy_tx(
                fixture.asset_id,
                &pool,
                owner_anchor,
                owner_anchor_value,
                &fixture.owner_script,
                p2sh_signature_script_for(&owner_redeem_script),
                auth_nonce,
                3 * SOMPI_PER_CRYPTIX,
                fixture.tx_fee,
            );
            let buy_in = vault_value - pool.vault_value_sompi;
            owner_anchor_value = owner_anchor_value.checked_sub(buy_in + fixture.tx_fee).expect("anchor should fund buy pressure");
            owner_anchor = TransactionOutpoint::new(buy_tx.id(), 1);
            expected_balance += token_out;
            buy_tx
        } else {
            let token_in = 1u128;
            let (_, cpay_out) = quote_sell(pool.virtual_cpay_reserves_sompi, pool.virtual_token_reserves, token_in, pool.fee_bps);
            assert!(cpay_out > 0, "pressure sell must produce a payout at step {step}");
            let sell_vault_value = pool.vault_value_sompi - cpay_out;
            owner_anchor_value = owner_anchor_value.checked_sub(fixture.tx_fee).expect("anchor should fund sell pressure");
            let sell_tx = payload_tx(
                vec![
                    TransactionInput::new(pool.vault_outpoint, vec![], 0, 0),
                    TransactionInput::new(owner_anchor, p2sh_signature_script_for(&owner_redeem_script), 0, 0),
                ],
                vec![
                    TransactionOutput::new(sell_vault_value, liquidity_vault_script()),
                    TransactionOutput::new(cpay_out, fixture.owner_script.clone()),
                    TransactionOutput::new(owner_anchor_value, fixture.owner_script.clone()),
                ],
                payload_sell_liquidity(1, auth_nonce, fixture.asset_id, pool.pool_nonce, token_in, cpay_out, 1),
            );
            owner_anchor = TransactionOutpoint::new(sell_tx.id(), 2);
            expected_balance -= token_in;
            sell_tx
        };

        ctx.simulated_time += ctx.consensus.params().target_time_per_block;
        let template = ctx.build_block_template_with_transactions(vec![tx], 9_100 + step, ctx.simulated_time);
        ctx.validate_and_insert_utxo_valid_block(template.block.to_immutable()).await;

        ctx.simulated_time += ctx.consensus.params().target_time_per_block;
        let settle_template = ctx.build_block_template(9_500 + step, ctx.simulated_time);
        ctx.validate_and_insert_utxo_valid_block(settle_template.block.to_immutable()).await;

        let atomic_after = ctx.consensus.virtual_atomic_state();
        let pool_after = atomic_after
            .assets
            .get(&fixture.asset_id)
            .and_then(|asset| asset.liquidity.as_ref())
            .expect("pool must exist after pressure step");
        assert_eq!(pool_after.pool_nonce, fixture.pool.pool_nonce + step + 1);
        assert_eq!(pool_after.vault_value_sompi, pool_after.real_cpay_reserves_sompi + pool_after.unclaimed_fee_total_sompi);
        assert_eq!(balance_of(&atomic_after, fixture.asset_id, fixture.owner_id), expected_balance);

        let sink = ctx.consensus.get_sink();
        let expected_root = atomic_after.canonical_hash();
        assert_eq!(
            ctx.consensus.selected_chain_atomic_hash_from_deltas_for_tests(sink),
            expected_root,
            "selected-chain Atomic deltas must replay to live state after pressure step {step}"
        );
        assert_eq!(
            ctx.consensus.atomic_root_record_hash_for_tests(sink),
            expected_root,
            "stored Atomic root must match live state after pressure step {step}"
        );
    }
}

#[tokio::test]
async fn mixed_atomic_and_native_templates_remain_utxo_valid_after_each_acceptance() {
    let (mut ctx, fixture) = setup_dual_owner_liquidity_pool().await;
    let (buy_tx, buy_token_out, _) = build_liquidity_buy_tx(
        fixture.asset_id,
        &fixture.pool,
        fixture.owner_anchor,
        fixture.owner_anchor_value,
        &fixture.owner_script,
        p2sh_signature_script(),
        1,
        10 * SOMPI_PER_CRYPTIX,
        fixture.tx_fee,
    );
    let second_owner_change = fixture.second_owner_anchor_value - fixture.tx_fee;
    let native_tx = Transaction::new(
        TX_VERSION,
        vec![TransactionInput::new(fixture.second_owner_anchor, p2sh_signature_script_for(&second_p2sh_redeem_script()), 0, 0)],
        vec![TransactionOutput::new(second_owner_change, fixture.second_owner_script.clone())],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let mixed_template = ctx.build_block_template_with_transactions(vec![native_tx, buy_tx.clone()], 400, ctx.simulated_time);
    ctx.validate_and_insert_utxo_valid_block(mixed_template.block.to_immutable()).await;

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let empty_after_mixed = ctx.build_block_template(401, ctx.simulated_time);
    ctx.validate_and_insert_utxo_valid_block(empty_after_mixed.block.to_immutable()).await;

    let atomic = ctx.consensus.virtual_atomic_state();
    let asset = atomic.assets.get(&fixture.asset_id).expect("liquidity asset should exist");
    let pool = asset.liquidity.as_ref().expect("pool should exist");
    assert_eq!(pool.pool_nonce, fixture.pool.pool_nonce + 1);
    assert_eq!(balance_of(&atomic, fixture.asset_id, fixture.owner_id), fixture.launch_token_out + buy_token_out);

    let owner_anchor = TransactionOutpoint::new(buy_tx.id(), 1);
    let owner_anchor_value = buy_tx.outputs[1].value;
    let token_in = 1u128;
    let (_, cpay_out) = quote_sell(pool.virtual_cpay_reserves_sompi, pool.virtual_token_reserves, token_in, 100);
    let sell_tx = payload_tx(
        vec![
            TransactionInput::new(pool.vault_outpoint, vec![], 0, 0),
            TransactionInput::new(owner_anchor, p2sh_signature_script(), 0, 0),
        ],
        vec![
            TransactionOutput::new(pool.vault_value_sompi - cpay_out, liquidity_vault_script()),
            TransactionOutput::new(cpay_out, fixture.owner_script.clone()),
            TransactionOutput::new(owner_anchor_value - fixture.tx_fee, fixture.owner_script.clone()),
        ],
        payload_sell_liquidity(1, 2, fixture.asset_id, pool.pool_nonce, token_in, cpay_out, 1),
    );

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let sell_template = ctx.build_block_template_with_transactions(vec![sell_tx], 402, ctx.simulated_time);
    ctx.validate_and_insert_utxo_valid_block(sell_template.block.to_immutable()).await;

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let empty_after_sell = ctx.build_block_template(403, ctx.simulated_time);
    ctx.validate_and_insert_utxo_valid_block(empty_after_sell.block.to_immutable()).await;
}

#[tokio::test]
async fn local_miner_extends_mixed_relay_block_with_valid_empty_templates() {
    let (mut ctx, fixture) = setup_dual_owner_liquidity_pool().await;
    let local_miner_data = ctx.miner_data.clone();
    let relay_miner_data = new_miner_data();
    ctx.miner_data = relay_miner_data;

    let (buy_tx, _, _) = build_liquidity_buy_tx(
        fixture.asset_id,
        &fixture.pool,
        fixture.owner_anchor,
        fixture.owner_anchor_value,
        &fixture.owner_script,
        p2sh_signature_script(),
        1,
        10 * SOMPI_PER_CRYPTIX,
        fixture.tx_fee,
    );
    let native_tx = Transaction::new(
        TX_VERSION,
        vec![TransactionInput::new(fixture.second_owner_anchor, p2sh_signature_script_for(&second_p2sh_redeem_script()), 0, 0)],
        vec![TransactionOutput::new(fixture.second_owner_anchor_value - fixture.tx_fee, fixture.second_owner_script.clone())],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let relayed_mixed = ctx.build_block_template_with_transactions(vec![native_tx, buy_tx], 4_300, ctx.simulated_time);
    ctx.validate_and_insert_utxo_valid_block(relayed_mixed.block.to_immutable()).await;

    ctx.miner_data = local_miner_data;
    for nonce in 4_301..4_304 {
        ctx.simulated_time += ctx.consensus.params().target_time_per_block;
        let local_empty = ctx.build_block_template(nonce, ctx.simulated_time);
        ctx.validate_and_insert_utxo_valid_block(local_empty.block.to_immutable()).await;
    }
}

#[tokio::test]
async fn template_build_repairs_stale_virtual_atomic_state_after_mixed_block() {
    let (mut ctx, fixture) = setup_dual_owner_liquidity_pool().await;
    let stale_atomic = {
        let virtual_stores = ctx.consensus.virtual_stores();
        let read = virtual_stores.read();
        let state = read.state.get().expect("virtual state before mixed block");
        (state.atomic_state.clone(), state.atomic_diff.clone())
    };

    let (buy_tx, _, _) = build_liquidity_buy_tx(
        fixture.asset_id,
        &fixture.pool,
        fixture.owner_anchor,
        fixture.owner_anchor_value,
        &fixture.owner_script,
        p2sh_signature_script(),
        1,
        10 * SOMPI_PER_CRYPTIX,
        fixture.tx_fee,
    );
    let native_tx = Transaction::new(
        TX_VERSION,
        vec![TransactionInput::new(fixture.second_owner_anchor, p2sh_signature_script_for(&second_p2sh_redeem_script()), 0, 0)],
        vec![TransactionOutput::new(fixture.second_owner_anchor_value - fixture.tx_fee, fixture.second_owner_script.clone())],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let mixed_template = ctx.build_block_template_with_transactions(vec![native_tx, buy_tx], 4_400, ctx.simulated_time);
    ctx.validate_and_insert_utxo_valid_block(mixed_template.block.to_immutable()).await;
    let expected_atomic_hash = ctx.consensus.virtual_atomic_state().canonical_hash();

    {
        let virtual_stores = ctx.consensus.virtual_stores();
        let mut write = virtual_stores.write();
        let mut corrupted = write.state.get().expect("virtual state after mixed block").as_ref().clone();
        corrupted.atomic_state = stale_atomic.0;
        corrupted.atomic_diff = stale_atomic.1;
        write.state.set(Arc::new(corrupted)).expect("corrupt virtual atomic state for regression test");
    }

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let empty_after_corruption = ctx.build_block_template(4_401, ctx.simulated_time);
    assert_eq!(
        ctx.consensus.virtual_atomic_state().canonical_hash(),
        expected_atomic_hash,
        "template building must repair a stale virtual Atomic root before serving miners"
    );
    ctx.validate_and_insert_utxo_valid_block(empty_after_corruption.block.to_immutable()).await;
}

#[tokio::test]
async fn template_build_repairs_corrupt_atomic_deltas_from_block_data() {
    let (mut ctx, fixture) = setup_dual_owner_liquidity_pool().await;

    let (buy_tx, _, _) = build_liquidity_buy_tx(
        fixture.asset_id,
        &fixture.pool,
        fixture.owner_anchor,
        fixture.owner_anchor_value,
        &fixture.owner_script,
        p2sh_signature_script(),
        1,
        10 * SOMPI_PER_CRYPTIX,
        fixture.tx_fee,
    );
    let native_tx = Transaction::new(
        TX_VERSION,
        vec![TransactionInput::new(fixture.second_owner_anchor, p2sh_signature_script_for(&second_p2sh_redeem_script()), 0, 0)],
        vec![TransactionOutput::new(fixture.second_owner_anchor_value - fixture.tx_fee, fixture.second_owner_script.clone())],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let mixed_template = ctx.build_block_template_with_transactions(vec![native_tx, buy_tx], 4_450, ctx.simulated_time);
    ctx.validate_and_insert_utxo_valid_block(mixed_template.block.to_immutable()).await;

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let accepting_template = ctx.build_block_template(4_451, ctx.simulated_time);
    ctx.validate_and_insert_utxo_valid_block(accepting_template.block.to_immutable()).await;

    let selected_parent = ctx.consensus.get_sink();
    let expected_atomic_hash = ctx.consensus.virtual_atomic_state().canonical_hash();
    ctx.consensus.clear_atomic_current_store_for_tests();
    ctx.consensus.overwrite_atomic_delta_with_empty_for_tests(selected_parent);

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let repaired_template = ctx.build_block_template(4_452, ctx.simulated_time);
    assert_eq!(
        ctx.consensus.virtual_atomic_state().canonical_hash(),
        expected_atomic_hash,
        "template building must rebuild bad selected-chain Atomic deltas from local acceptance/block data"
    );
    assert_eq!(
        ctx.consensus.selected_chain_atomic_hash_from_deltas_for_tests(selected_parent),
        expected_atomic_hash,
        "repaired selected-chain Atomic deltas must replay to the same root without another block-data rebuild"
    );
    ctx.validate_and_insert_utxo_valid_block(repaired_template.block.to_immutable()).await;
}

#[tokio::test]
async fn template_repair_replays_utxos_created_and_spent_inside_same_acceptance_diff() {
    let mut ctx = liquidity_test_context();
    let owner_redeem_script = p2sh_redeem_script();
    let owner_script = cryptix_txscript::pay_to_script_hash_script(&owner_redeem_script);
    let owner_id = atomic_owner_id_from_script(&owner_script).expect("owner id should derive from P2SH");
    ctx.miner_data = MinerData::new(owner_script.clone(), vec![]);

    for _ in 0..4 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await;
    }
    let fork_base = ctx.consensus.get_sink();
    let (funding_outpoint, funding_entry) = find_virtual_utxo_by_script(&ctx, &owner_script);
    let tx_fee = 10_000u64;
    let create_change_value = funding_entry.amount - tx_fee;
    let create_tx = payload_tx(
        vec![TransactionInput::new(funding_outpoint, p2sh_signature_script_for(&owner_redeem_script), 0, 0)],
        vec![TransactionOutput::new(create_change_value, owner_script.clone())],
        payload_create_asset(0, 1, owner_id, b"ReplayLocal", b"RPL"),
    );
    let create_change_outpoint = TransactionOutpoint::new(create_tx.id(), 0);
    let mut spend_created_output_tx = Transaction::new(
        TX_VERSION,
        vec![TransactionInput::new(create_change_outpoint, p2sh_signature_script_for(&owner_redeem_script), 0, 0)],
        vec![TransactionOutput::new(create_change_value - tx_fee, owner_script.clone())],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );
    spend_created_output_tx.finalize();

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let side_create =
        ctx.build_utxo_valid_block_with_parents_and_transactions(vec![fork_base], vec![create_tx.clone()], 5_000, ctx.simulated_time);
    let side_create_hash = side_create.header.hash;
    ctx.validate_and_insert_block(side_create.to_immutable()).await;

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let side_spend = ctx.build_utxo_valid_block_with_parents_and_transactions(
        vec![side_create_hash],
        vec![spend_created_output_tx.clone()],
        5_001,
        ctx.simulated_time,
    );
    let side_spend_hash = side_spend.header.hash;
    ctx.validate_and_insert_block(side_spend.to_immutable()).await;

    let mut selected_tip = fork_base;
    for nonce in 5_010..5_016 {
        ctx.simulated_time += ctx.consensus.params().target_time_per_block;
        let extension =
            ctx.build_utxo_valid_block_with_parents_and_transactions(vec![selected_tip], vec![], nonce, ctx.simulated_time);
        selected_tip = extension.header.hash;
        ctx.validate_and_insert_block(extension.to_immutable()).await;
    }
    assert_eq!(ctx.consensus.get_sink(), selected_tip, "test setup must keep the plain selected chain ahead of the side branch");

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let merge_side_branch = ctx.build_utxo_valid_block_with_parents_and_transactions(
        vec![selected_tip, side_spend_hash],
        vec![],
        5_020,
        ctx.simulated_time,
    );
    let merge_hash = merge_side_branch.header.hash;
    ctx.validate_and_insert_utxo_valid_block(merge_side_branch.to_immutable()).await;
    assert_eq!(ctx.consensus.get_sink(), merge_hash, "merge block must be the selected parent for this repair regression");

    let acceptance_data = ctx.consensus.get_block_acceptance_data(merge_hash).expect("merge acceptance data should exist");
    let accepted_txids: Vec<_> = acceptance_data
        .iter()
        .flat_map(|block_acceptance| block_acceptance.accepted_transactions.iter())
        .map(|tx| tx.transaction_id)
        .collect();
    assert!(accepted_txids.contains(&create_tx.id()), "merge block must accept the CAT create tx from the side branch");
    assert!(
        accepted_txids.contains(&spend_created_output_tx.id()),
        "merge block must accept the tx spending a UTXO created earlier in the same acceptance diff"
    );

    let selected_parent = ctx.consensus.get_sink();
    let expected_atomic_hash = ctx.consensus.virtual_atomic_state().canonical_hash();
    assert_eq!(
        ctx.consensus.atomic_root_record_hash_for_tests(selected_parent),
        expected_atomic_hash,
        "test setup must start from a selected-parent Atomic root record that matches live virtual state"
    );
    ctx.consensus.clear_atomic_current_store_for_tests();
    ctx.consensus.overwrite_atomic_delta_with_empty_for_tests(selected_parent);

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let repaired_template = ctx.build_block_template(5_021, ctx.simulated_time);
    assert_eq!(
        ctx.consensus.selected_chain_atomic_hash_from_deltas_for_tests(selected_parent),
        expected_atomic_hash,
        "block-data repair must persist deltas that replay through intra-acceptance UTXO create/spend chains"
    );
    ctx.validate_and_insert_utxo_valid_block(repaired_template.block.to_immutable()).await;
}

#[tokio::test]
async fn template_build_refuses_unrepairable_atomic_commitment_base() {
    let (mut ctx, fixture) = setup_dual_owner_liquidity_pool().await;

    let (buy_tx, _, _) = build_liquidity_buy_tx(
        fixture.asset_id,
        &fixture.pool,
        fixture.owner_anchor,
        fixture.owner_anchor_value,
        &fixture.owner_script,
        p2sh_signature_script(),
        1,
        10 * SOMPI_PER_CRYPTIX,
        fixture.tx_fee,
    );
    let native_tx = Transaction::new(
        TX_VERSION,
        vec![TransactionInput::new(fixture.second_owner_anchor, p2sh_signature_script_for(&second_p2sh_redeem_script()), 0, 0)],
        vec![TransactionOutput::new(fixture.second_owner_anchor_value - fixture.tx_fee, fixture.second_owner_script.clone())],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let mixed_template = ctx.build_block_template_with_transactions(vec![native_tx, buy_tx], 4_470, ctx.simulated_time);
    ctx.validate_and_insert_utxo_valid_block(mixed_template.block.to_immutable()).await;

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let accepting_template = ctx.build_block_template(4_471, ctx.simulated_time);
    ctx.validate_and_insert_utxo_valid_block(accepting_template.block.to_immutable()).await;

    let selected_parent = ctx.consensus.get_sink();
    let actual_root = ctx.consensus.virtual_atomic_state().canonical_hash();
    let mut bogus_root = [0x42u8; 32];
    if bogus_root == actual_root {
        bogus_root[0] ^= 0x01;
    }
    ctx.consensus.clear_atomic_current_store_for_tests();
    ctx.consensus.overwrite_atomic_root_with_hash_for_tests(selected_parent, bogus_root);

    let result = ctx.consensus.build_block_template(
        ctx.miner_data.clone(),
        Box::new(OnetimeTxSelector::new(Default::default())),
        TemplateBuildMode::Standard,
    );
    assert!(
        matches!(result, Err(RuleError::KnownInvalid)),
        "template building must refuse mining when the selected-parent Atomic prefix cannot be reconstructed"
    );
}

#[tokio::test]
async fn invalid_template_shaped_child_does_not_reapply_virtual_atomic_delta() {
    let (mut ctx, fixture) = setup_dual_owner_liquidity_pool().await;
    let (buy_tx, _, _) = build_liquidity_buy_tx(
        fixture.asset_id,
        &fixture.pool,
        fixture.owner_anchor,
        fixture.owner_anchor_value,
        &fixture.owner_script,
        p2sh_signature_script(),
        1,
        10 * SOMPI_PER_CRYPTIX,
        fixture.tx_fee,
    );

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let mixed_template = ctx.build_block_template_with_transactions(vec![buy_tx], 4_500, ctx.simulated_time);
    ctx.validate_and_insert_utxo_valid_block(mixed_template.block.to_immutable()).await;
    let selected_parent = ctx.consensus.get_sink();
    let expected_atomic_hash = ctx.consensus.virtual_atomic_state().canonical_hash();

    for nonce in 4_501..4_504 {
        ctx.simulated_time += ctx.consensus.params().target_time_per_block;
        let mut invalid_template = ctx.build_block_template(nonce, ctx.simulated_time);
        assert_eq!(invalid_template.selected_parent_hash, selected_parent);
        invalid_template.block.header.utxo_commitment = Hash::from_bytes([nonce as u8; 32]);
        invalid_template.block.header.finalize();
        let invalid_hash = invalid_template.block.header.hash;
        let status = ctx.consensus.validate_and_insert_block(invalid_template.block.to_immutable()).virtual_state_task.await.unwrap();
        assert_eq!(status, BlockStatus::StatusDisqualifiedFromChain);
        assert_eq!(
            ctx.consensus.virtual_atomic_state().canonical_hash(),
            expected_atomic_hash,
            "disqualified template-shaped child {invalid_hash} must not advance or reapply virtual Atomic state"
        );
        assert_eq!(ctx.consensus.get_sink(), selected_parent);
    }

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let valid_extension = ctx.build_block_template(4_504, ctx.simulated_time);
    ctx.validate_and_insert_utxo_valid_block(valid_extension.block.to_immutable()).await;
}

#[tokio::test]
async fn same_pool_nonce_chain_across_successive_blocks_remains_utxo_valid() {
    let (mut ctx, fixture) = setup_dual_owner_liquidity_pool().await;
    let (buy_1, token_out_1, _) = build_liquidity_buy_tx(
        fixture.asset_id,
        &fixture.pool,
        fixture.owner_anchor,
        fixture.owner_anchor_value,
        &fixture.owner_script,
        p2sh_signature_script(),
        1,
        10 * SOMPI_PER_CRYPTIX,
        fixture.tx_fee,
    );

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let first_template = ctx.build_block_template_with_transactions(vec![buy_1], 404, ctx.simulated_time);
    ctx.validate_and_insert_utxo_valid_block(first_template.block.to_immutable()).await;

    let atomic_after_first = ctx.consensus.virtual_atomic_state();
    let asset_after_first = atomic_after_first.assets.get(&fixture.asset_id).expect("liquidity asset should exist");
    let pool_after_buy_1 = asset_after_first.liquidity.as_ref().expect("pool should exist").clone();
    assert_eq!(pool_after_buy_1.pool_nonce, fixture.pool.pool_nonce + 1);
    assert_eq!(balance_of(&atomic_after_first, fixture.asset_id, fixture.owner_id), fixture.launch_token_out + token_out_1);

    let (buy_2, token_out_2, vault_value_2) = build_liquidity_buy_tx(
        fixture.asset_id,
        &pool_after_buy_1,
        fixture.second_owner_anchor,
        fixture.second_owner_anchor_value,
        &fixture.second_owner_script,
        p2sh_signature_script_for(&second_p2sh_redeem_script()),
        1,
        20 * SOMPI_PER_CRYPTIX,
        fixture.tx_fee,
    );

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let second_template = ctx.build_block_template_with_transactions(vec![buy_2.clone()], 405, ctx.simulated_time);
    ctx.validate_and_insert_utxo_valid_block(second_template.block.to_immutable()).await;

    let atomic = ctx.consensus.virtual_atomic_state();
    let asset = atomic.assets.get(&fixture.asset_id).expect("liquidity asset should exist");
    let pool = asset.liquidity.as_ref().expect("pool should exist");
    assert_eq!(pool.pool_nonce, fixture.pool.pool_nonce + 2);
    assert_eq!(pool.vault_outpoint, TransactionOutpoint::new(buy_2.id(), 0));
    assert_eq!(pool.vault_value_sompi, vault_value_2);
    assert_eq!(balance_of(&atomic, fixture.asset_id, fixture.owner_id), fixture.launch_token_out + token_out_1);
    assert_eq!(balance_of(&atomic, fixture.asset_id, fixture.second_owner_id), token_out_2);
}

#[tokio::test]
async fn liquidity_parallel_vault_conflict_applies_only_one_branch() {
    let (mut ctx, fixture) = setup_dual_owner_liquidity_pool().await;
    let (owner_buy_tx, owner_token_out, owner_vault_value) = build_liquidity_buy_tx(
        fixture.asset_id,
        &fixture.pool,
        fixture.owner_anchor,
        fixture.owner_anchor_value,
        &fixture.owner_script,
        p2sh_signature_script(),
        1,
        10 * SOMPI_PER_CRYPTIX,
        fixture.tx_fee,
    );
    let (second_buy_tx, second_token_out, second_vault_value) = build_liquidity_buy_tx(
        fixture.asset_id,
        &fixture.pool,
        fixture.second_owner_anchor,
        fixture.second_owner_anchor_value,
        &fixture.second_owner_script,
        p2sh_signature_script_for(&second_p2sh_redeem_script()),
        1,
        20 * SOMPI_PER_CRYPTIX,
        fixture.tx_fee,
    );

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let owner_buy_block = ctx.build_utxo_valid_block_with_parents_and_transactions(
        vec![fixture.create_block_hash],
        vec![owner_buy_tx],
        200,
        ctx.simulated_time,
    );
    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let second_buy_block = ctx.build_utxo_valid_block_with_parents_and_transactions(
        vec![fixture.create_block_hash],
        vec![second_buy_tx],
        201,
        ctx.simulated_time,
    );

    ctx.validate_and_insert_block(owner_buy_block.to_immutable()).await;
    ctx.validate_and_insert_block(second_buy_block.to_immutable()).await;

    let atomic = ctx.consensus.virtual_atomic_state();
    let asset = atomic.assets.get(&fixture.asset_id).expect("liquidity asset should exist");
    let pool = asset.liquidity.as_ref().expect("pool should exist");
    assert_eq!(pool.pool_nonce, 2);

    match pool.vault_value_sompi {
        value if value == owner_vault_value => {
            assert_eq!(balance_of(&atomic, fixture.asset_id, fixture.owner_id), fixture.launch_token_out + owner_token_out);
            assert_eq!(balance_of(&atomic, fixture.asset_id, fixture.second_owner_id), 0);
        }
        value if value == second_vault_value => {
            assert_eq!(balance_of(&atomic, fixture.asset_id, fixture.owner_id), fixture.launch_token_out);
            assert_eq!(balance_of(&atomic, fixture.asset_id, fixture.second_owner_id), second_token_out);
        }
        value => panic!("unexpected vault value after parallel conflict: {value}"),
    }
}

#[tokio::test]
async fn liquidity_same_pool_nonce_parallel_blocks_apply_once_when_seen_out_of_order() {
    let (mut ctx, fixture) = setup_dual_owner_liquidity_pool().await;
    let (owner_buy_tx, owner_token_out, owner_vault_value) = build_liquidity_buy_tx(
        fixture.asset_id,
        &fixture.pool,
        fixture.owner_anchor,
        fixture.owner_anchor_value,
        &fixture.owner_script,
        p2sh_signature_script(),
        1,
        10 * SOMPI_PER_CRYPTIX,
        fixture.tx_fee,
    );
    let (second_buy_tx, second_token_out, second_vault_value) = build_liquidity_buy_tx(
        fixture.asset_id,
        &fixture.pool,
        fixture.second_owner_anchor,
        fixture.second_owner_anchor_value,
        &fixture.second_owner_script,
        p2sh_signature_script_for(&second_p2sh_redeem_script()),
        1,
        20 * SOMPI_PER_CRYPTIX,
        fixture.tx_fee,
    );

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let owner_buy_block = ctx.build_utxo_valid_block_with_parents_and_transactions(
        vec![fixture.create_block_hash],
        vec![owner_buy_tx],
        250,
        ctx.simulated_time,
    );
    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let second_buy_block = ctx.build_utxo_valid_block_with_parents_and_transactions(
        vec![fixture.create_block_hash],
        vec![second_buy_tx],
        251,
        ctx.simulated_time,
    );

    ctx.validate_and_insert_block(second_buy_block.to_immutable()).await;
    ctx.validate_and_insert_block(owner_buy_block.to_immutable()).await;

    let atomic = ctx.consensus.virtual_atomic_state();
    let asset = atomic.assets.get(&fixture.asset_id).expect("liquidity asset should exist");
    let pool = asset.liquidity.as_ref().expect("pool should exist");
    assert_eq!(pool.pool_nonce, fixture.pool.pool_nonce + 1);

    let owner_balance = balance_of(&atomic, fixture.asset_id, fixture.owner_id);
    let second_owner_balance = balance_of(&atomic, fixture.asset_id, fixture.second_owner_id);
    let applied_buys = usize::from(owner_balance == fixture.launch_token_out + owner_token_out)
        + usize::from(second_owner_balance == second_token_out);
    assert_eq!(applied_buys, 1, "exactly one same-pool same-nonce buy may affect atomic state");

    match pool.vault_value_sompi {
        value if value == owner_vault_value => {
            assert_eq!(owner_balance, fixture.launch_token_out + owner_token_out);
            assert_eq!(second_owner_balance, 0);
        }
        value if value == second_vault_value => {
            assert_eq!(owner_balance, fixture.launch_token_out);
            assert_eq!(second_owner_balance, second_token_out);
        }
        value => panic!("unexpected vault value after out-of-order parallel conflict: {value}"),
    }
}

#[tokio::test]
async fn liquidity_reorg_switches_to_winning_conflicting_vault_branch() {
    let (mut ctx, fixture) = setup_dual_owner_liquidity_pool().await;
    let (owner_buy_tx, owner_token_out, _) = build_liquidity_buy_tx(
        fixture.asset_id,
        &fixture.pool,
        fixture.owner_anchor,
        fixture.owner_anchor_value,
        &fixture.owner_script,
        p2sh_signature_script(),
        1,
        10 * SOMPI_PER_CRYPTIX,
        fixture.tx_fee,
    );
    let (second_buy_tx, second_token_out, second_vault_value) = build_liquidity_buy_tx(
        fixture.asset_id,
        &fixture.pool,
        fixture.second_owner_anchor,
        fixture.second_owner_anchor_value,
        &fixture.second_owner_script,
        p2sh_signature_script_for(&second_p2sh_redeem_script()),
        1,
        20 * SOMPI_PER_CRYPTIX,
        fixture.tx_fee,
    );

    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let owner_buy_block = ctx.build_utxo_valid_block_with_parents_and_transactions(
        vec![fixture.create_block_hash],
        vec![owner_buy_tx.clone()],
        300,
        ctx.simulated_time,
    );
    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let second_buy_block = ctx.build_utxo_valid_block_with_parents_and_transactions(
        vec![fixture.create_block_hash],
        vec![second_buy_tx.clone()],
        301,
        ctx.simulated_time,
    );
    let mut second_branch_tip = second_buy_block.header.hash;

    ctx.validate_and_insert_block(owner_buy_block.to_immutable()).await;
    let atomic = ctx.consensus.virtual_atomic_state();
    assert_eq!(balance_of(&atomic, fixture.asset_id, fixture.owner_id), fixture.launch_token_out + owner_token_out);
    assert_eq!(balance_of(&atomic, fixture.asset_id, fixture.second_owner_id), 0);

    ctx.validate_and_insert_block(second_buy_block.to_immutable()).await;
    for nonce in 302..305 {
        ctx.simulated_time += ctx.consensus.params().target_time_per_block;
        let extension =
            ctx.build_utxo_valid_block_with_parents_and_transactions(vec![second_branch_tip], vec![], nonce, ctx.simulated_time);
        second_branch_tip = extension.header.hash;
        ctx.validate_and_insert_block(extension.to_immutable()).await;
    }

    assert!(ctx.consensus.reachability_service().is_chain_ancestor_of(second_branch_tip, ctx.consensus.get_sink()));
    let atomic = ctx.consensus.virtual_atomic_state();
    let asset = atomic.assets.get(&fixture.asset_id).expect("liquidity asset should exist");
    let pool = asset.liquidity.as_ref().expect("pool should exist");
    assert_eq!(pool.pool_nonce, 2);
    assert_eq!(pool.vault_value_sompi, second_vault_value);
    assert_eq!(balance_of(&atomic, fixture.asset_id, fixture.owner_id), fixture.launch_token_out);
    assert_eq!(balance_of(&atomic, fixture.asset_id, fixture.second_owner_id), second_token_out);

    let winning_pool = pool.clone();
    let initial_vault_entry = UtxoEntry::new(fixture.pool.vault_value_sompi, liquidity_vault_script(), UNACCEPTED_DAA_SCORE, false);
    let winning_vault_entry = UtxoEntry::new(winning_pool.vault_value_sompi, liquidity_vault_script(), UNACCEPTED_DAA_SCORE, false);
    let owner_anchor_entry = UtxoEntry::new(fixture.owner_anchor_value, fixture.owner_script.clone(), UNACCEPTED_DAA_SCORE, false);

    let mut stale_losing_branch_buy =
        MutableTransaction::with_entries(Arc::new(owner_buy_tx), vec![initial_vault_entry, owner_anchor_entry.clone()]);
    ctx.consensus
        .validate_mempool_transaction(&mut stale_losing_branch_buy, &TransactionValidationArgs::default())
        .expect_err("losing-branch vault spend must be rejected after the liquidity reorg");

    let (fresh_owner_buy_tx, _, _) = build_liquidity_buy_tx(
        fixture.asset_id,
        &winning_pool,
        fixture.owner_anchor,
        fixture.owner_anchor_value,
        &fixture.owner_script,
        p2sh_signature_script(),
        1,
        5 * SOMPI_PER_CRYPTIX,
        fixture.tx_fee,
    );
    let mut fresh_winning_branch_buy =
        MutableTransaction::with_entries(Arc::new(fresh_owner_buy_tx), vec![winning_vault_entry, owner_anchor_entry]);
    ctx.consensus
        .validate_mempool_transaction(&mut fresh_winning_branch_buy, &TransactionValidationArgs::default())
        .expect("fresh buy against the winning vault state must validate after the liquidity reorg");

    let atomic_after_mempool = ctx.consensus.virtual_atomic_state();
    let pool_after_mempool =
        atomic_after_mempool.assets.get(&fixture.asset_id).and_then(|asset| asset.liquidity.as_ref()).expect("pool should exist");
    assert_eq!(pool_after_mempool.pool_nonce, winning_pool.pool_nonce);
    assert_eq!(pool_after_mempool.vault_outpoint, winning_pool.vault_outpoint);
    assert_eq!(balance_of(&atomic_after_mempool, fixture.asset_id, fixture.owner_id), fixture.launch_token_out);
    assert_eq!(balance_of(&atomic_after_mempool, fixture.asset_id, fixture.second_owner_id), second_token_out);
}

fn new_miner_data() -> MinerData {
    let secp = secp256k1::Secp256k1::new();
    let mut rng = rand::thread_rng();
    let (_sk, pk) = secp.generate_keypair(&mut rng);
    let script = ScriptVec::from_slice(&pk.serialize());
    MinerData::new(ScriptPublicKey::new(0, script), vec![])
}
