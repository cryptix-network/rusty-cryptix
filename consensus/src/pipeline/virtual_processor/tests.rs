use crate::{
    consensus::test_consensus::TestConsensus,
    model::{
        services::reachability::ReachabilityService,
        stores::atomic_state::{AtomicAssetClass, AtomicBalanceKey, AtomicLiquidityPoolState},
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
    config::{params::MAINNET_PARAMS, ConfigBuilder},
    constants::{SOMPI_PER_CRYPTIX, TX_VERSION},
    subnets::{SUBNETWORK_ID_NATIVE, SUBNETWORK_ID_PAYLOAD},
    tx::{MutableTransaction, ScriptPublicKey, ScriptVec, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput},
    BlockHashSet,
};
use cryptix_hashes::Hash;
use std::{collections::VecDeque, thread::JoinHandle};

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
    assert_eq!(BlockHashSet::from_iter([sink, disqualified_tip]), BlockHashSet::from_iter(ctx.consensus.get_tips().into_iter()));
    assert!(!ctx.consensus.get_virtual_parents().contains(&disqualified_tip));
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
    assert_eq!(
        BlockHashSet::from_iter([sink, disqualified_tip_1, disqualified_tip_2]),
        BlockHashSet::from_iter(ctx.consensus.get_tips().into_iter())
    );
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

const INITIAL_LIQUIDITY_VIRTUAL_CPAY_RESERVES_SOMPI: u64 = 250_000_000_000_000;

fn initial_liquidity_virtual_token_reserves(max_supply: u128) -> u128 {
    max_supply * 6 / 5
}

fn quote_sell(virtual_cpay_reserves_sompi: u64, virtual_token_reserves: u128, token_in: u128, fee_bps: u16) -> (u64, u64) {
    let y_after = virtual_token_reserves + token_in;
    let x_before = u128::from(virtual_cpay_reserves_sompi);
    let x_after = (x_before * virtual_token_reserves) / y_after;
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
    let launch_buy = 10 * SOMPI_PER_CRYPTIX;
    let tx_fee = 10_000u64;
    let owner_anchor_value = 50 * SOMPI_PER_CRYPTIX;
    let second_owner_anchor_value = 50 * SOMPI_PER_CRYPTIX;
    let (_, launch_token_out) = quote_buy(
        max_supply,
        INITIAL_LIQUIDITY_VIRTUAL_CPAY_RESERVES_SOMPI,
        initial_liquidity_virtual_token_reserves(max_supply),
        launch_buy,
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
    buy_in: u64,
    tx_fee: u64,
) -> (Transaction, u128, u64) {
    let (_, token_out) =
        quote_buy(pool.real_token_reserves, pool.virtual_cpay_reserves_sompi, pool.virtual_token_reserves, buy_in, pool.fee_bps);
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
    let launch_buy = 10 * SOMPI_PER_CRYPTIX;
    let tx_fee = 10_000u64;
    let (_, launch_token_out) = quote_buy(
        max_supply,
        INITIAL_LIQUIDITY_VIRTUAL_CPAY_RESERVES_SOMPI,
        initial_liquidity_virtual_token_reserves(max_supply),
        launch_buy,
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

    let buy_in = 10 * SOMPI_PER_CRYPTIX;
    let (_, buy_token_out) =
        quote_buy(pool.real_token_reserves, pool.virtual_cpay_reserves_sompi, pool.virtual_token_reserves, buy_in, fee_bps);
    let buy_vault_value = pool.vault_value_sompi + buy_in;
    owner_anchor_value -= buy_in + tx_fee;
    let buy_payload = payload_buy_liquidity(1, 2, asset_id, pool.pool_nonce, buy_in, 1);
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
    let sell_payload = payload_sell_liquidity(1, 3, asset_id, pool.pool_nonce, token_in, cpay_out, 1);
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
    let claim_payload = payload_claim_liquidity(1, 4, asset_id, pool.pool_nonce, 0, claim_amount, 1);
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
async fn liquidity_parallel_vault_conflict_applies_only_one_branch() {
    let (mut ctx, fixture) = setup_dual_owner_liquidity_pool().await;
    let (owner_buy_tx, owner_token_out, owner_vault_value) = build_liquidity_buy_tx(
        fixture.asset_id,
        &fixture.pool,
        fixture.owner_anchor,
        fixture.owner_anchor_value,
        &fixture.owner_script,
        p2sh_signature_script(),
        2,
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
async fn liquidity_reorg_switches_to_winning_conflicting_vault_branch() {
    let (mut ctx, fixture) = setup_dual_owner_liquidity_pool().await;
    let (owner_buy_tx, owner_token_out, _) = build_liquidity_buy_tx(
        fixture.asset_id,
        &fixture.pool,
        fixture.owner_anchor,
        fixture.owner_anchor_value,
        &fixture.owner_script,
        p2sh_signature_script(),
        2,
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
        300,
        ctx.simulated_time,
    );
    ctx.simulated_time += ctx.consensus.params().target_time_per_block;
    let second_buy_block = ctx.build_utxo_valid_block_with_parents_and_transactions(
        vec![fixture.create_block_hash],
        vec![second_buy_tx],
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
}

fn new_miner_data() -> MinerData {
    let secp = secp256k1::Secp256k1::new();
    let mut rng = rand::thread_rng();
    let (_sk, pk) = secp.generate_keypair(&mut rng);
    let script = ScriptVec::from_slice(&pk.serialize());
    MinerData::new(ScriptPublicKey::new(0, script), vec![])
}
