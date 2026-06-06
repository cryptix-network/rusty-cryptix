use super::*;
use cryptix_consensus_core::{
    api::ConsensusApi, config::params::SIMNET_PARAMS, constants::MAX_TX_IN_SEQUENCE_NUM, subnets::SubnetworkId,
};
use std::env;

const STRESS_DEFAULT_ROUNDS: usize = 45;
const STRESS_WALLET_COUNT: usize = 8;
const STRESS_COINBASE_BLOCKS: usize = 80;
const STRESS_OWNER_FANOUT_INPUTS: usize = 30;
const STRESS_FANOUT_OUTPUTS: usize = 10;
const STRESS_WALLET_FUNDING_UTXOS: usize = 14;
const STRESS_TX_FEE: u64 = 1_000;
const STRESS_BASE_INITIAL_SUPPLY: u128 = 1_000_000;
const STRESS_BASE_MAX_SUPPLY: u64 = 100_000_000;
const STRESS_LIQUIDITY_MAX_SUPPLY: u64 = 1_000_000;
const STRESS_EXPECTED_STATE_HASH: &str = "158620cc4029cf8b001a2410266a62142749bf2bbec6a13f5778d1500ec2a1f8";
const STRESS_EXPECTED_TOKEN_AUDIT_HASH: &str = "2e21f9ec6ab0556bde6c541dccf34a85bb2d7e79bdee88ae48c8446cdd341ff3";
const OWNER_INDEX: usize = 0;
const RECEIVER_INDEX: usize = 1;
const WALLET_START_INDEX: usize = 2;

#[derive(Clone)]
struct StressUtxo {
    outpoint: TransactionOutpoint,
    amount: u64,
    redeem_script: Vec<u8>,
}

struct StressActor {
    label: String,
    redeem_script: Vec<u8>,
    script_public_key: ScriptPublicKey,
    owner_id: [u8; 32],
    recipient_payload: Vec<u8>,
    utxos: Vec<StressUtxo>,
    next_owner_nonce: u64,
    expected_base_balance: u128,
}

#[derive(Clone, Copy)]
struct StressPayment {
    actor_index: usize,
    amount: u64,
}

#[derive(Clone)]
struct StressBundle {
    tx: Transaction,
    owners: Vec<Option<usize>>,
}

struct StressAssetExpectation {
    asset_id: [u8; 32],
    creator_owner_id: [u8; 32],
    mint_authority_owner_id: [u8; 32],
    initial_owner_id: [u8; 32],
    initial_amount: u128,
}

#[derive(Default)]
struct StressCounters {
    native: usize,
    wallet_native: usize,
    messenger: usize,
    wallet_messenger: usize,
    raw_payloads: usize,
    wallet_raw_payloads: usize,
    token_creates: usize,
    wallet_token_creates: usize,
    base_ops: usize,
    buys: usize,
    sells: usize,
    claims: usize,
    max_block_template_txs: usize,
    mined_stress_blocks: usize,
}

#[tokio::test]
async fn atomic_deterministic_stress_cross_check_state_hash() {
    let config = stress_consensus_config();
    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let mut actors = stress_actors();
    ctx.miner_data = MinerData::new(actors[OWNER_INDEX].script_public_key.clone(), b"go-atomic-stress".to_vec());

    let mut counters = StressCounters::default();
    let mut next_block_nonce = 1u64;
    let mut first_coinbase_tx_id = [0u8; 32];

    for i in 0..STRESS_COINBASE_BLOCKS {
        let block = mine_stress_block(&mut ctx, Vec::new(), &mut next_block_nonce).await;
        if i == 0 {
            first_coinbase_tx_id = block.transactions[0].id().as_bytes();
            let output_values: Vec<_> = block.transactions[0].outputs.iter().map(|output| output.value).collect();
            eprintln!(
                "rust first coinbase details: outputs={} values={:?} payload={}",
                block.transactions[0].outputs.len(),
                output_values,
                faster_hex::hex_string(&block.transactions[0].payload)
            );
        }
        record_coinbase_outputs(&block, &mut actors, OWNER_INDEX);
        counters.mined_stress_blocks += 1;
    }

    let split_bundles = build_owner_fanout_transactions(&mut actors);
    mine_stress_bundles(&mut ctx, &split_bundles, &mut next_block_nonce).await;
    record_stress_bundles(&split_bundles, &mut actors);
    counters.native += split_bundles.len();
    counters.max_block_template_txs = counters.max_block_template_txs.max(split_bundles.len() + 1);
    counters.mined_stress_blocks += 1;

    let funding_bundles = build_wallet_funding_transactions(&mut actors);
    mine_stress_bundles(&mut ctx, &funding_bundles, &mut next_block_nonce).await;
    record_stress_bundles(&funding_bundles, &mut actors);
    counters.native += funding_bundles.len();
    counters.max_block_template_txs = counters.max_block_template_txs.max(funding_bundles.len() + 1);
    counters.mined_stress_blocks += 1;

    let mut setup_bundles = Vec::with_capacity(2);
    let mut created_assets = Vec::new();

    let base_payload = stress_payload_create_asset_with_mint(
        actors[OWNER_INDEX].next_owner_nonce,
        0,
        1,
        STRESS_BASE_MAX_SUPPLY,
        actors[OWNER_INDEX].owner_id,
        actors[OWNER_INDEX].owner_id,
        STRESS_BASE_INITIAL_SUPPLY,
        "Stress Base",
        "GSTB",
        b"go deterministic base asset",
    );
    actors[OWNER_INDEX].next_owner_nonce += 1;
    let base_bundle = build_single_input_payload_tx(&mut actors, OWNER_INDEX, base_payload, &[], STRESS_TX_FEE);
    let base_asset_id = base_bundle.tx.id().as_bytes();
    actors[OWNER_INDEX].expected_base_balance = STRESS_BASE_INITIAL_SUPPLY;
    setup_bundles.push(base_bundle);

    let liquidity_payload = stress_payload_create_liquidity(
        actors[OWNER_INDEX].next_owner_nonce,
        STRESS_LIQUIDITY_MAX_SUPPLY,
        &actors[OWNER_INDEX].recipient_payload,
        "Stress Liquidity",
        "GSLQ",
        b"go deterministic liquidity asset",
    );
    actors[OWNER_INDEX].next_owner_nonce += 1;
    let liquidity_bundle = build_create_liquidity_transaction(&mut actors, OWNER_INDEX, liquidity_payload);
    let liquidity_asset_id = liquidity_bundle.tx.id().as_bytes();
    setup_bundles.push(liquidity_bundle);
    eprintln!(
        "rust deterministic atomic stress ids: owner_id={} first_coinbase_tx={} base_asset_id={} liquidity_asset_id={}",
        faster_hex::hex_string(&actors[OWNER_INDEX].owner_id),
        faster_hex::hex_string(&first_coinbase_tx_id),
        faster_hex::hex_string(&base_asset_id),
        faster_hex::hex_string(&liquidity_asset_id)
    );

    mine_stress_bundles(&mut ctx, &setup_bundles, &mut next_block_nonce).await;
    record_stress_bundles(&setup_bundles, &mut actors);
    log_stress_checkpoint(&ctx, "after_setup");
    counters.token_creates += 1;
    counters.max_block_template_txs = counters.max_block_template_txs.max(setup_bundles.len() + 1);
    counters.mined_stress_blocks += 1;

    let mut base_asset_nonce = 1u64;
    let mut liquidity_asset_nonce = 1u64;
    let rounds = stress_rounds_from_env();

    for round in 0..rounds {
        let mut phase_bundles = Vec::with_capacity(80);

        for i in 0..4 {
            phase_bundles.push(build_native_transfer_tx(
                &mut actors,
                OWNER_INDEX,
                OWNER_INDEX,
                40_000 + (round as u64 * 37) + (i as u64 * 11),
                STRESS_TX_FEE,
            ));
            counters.native += 1;
        }

        for i in 0..4 {
            let payload = stress_messenger_payload(round, i, &actors[OWNER_INDEX].owner_id, 96 + (round + i) % 64);
            phase_bundles.push(build_single_input_payload_tx(&mut actors, OWNER_INDEX, payload, &[], STRESS_TX_FEE));
            counters.messenger += 1;
        }

        for i in 0..2 {
            let payload = stress_raw_payload(round, i, 160 + (round + i) % 96);
            phase_bundles.push(build_single_input_payload_tx(&mut actors, OWNER_INDEX, payload, &[], STRESS_TX_FEE));
            counters.raw_payloads += 1;
        }

        for i in 0..STRESS_WALLET_COUNT {
            let wallet_index = WALLET_START_INDEX + i;
            let to_index = WALLET_START_INDEX + ((i + round + 1) % STRESS_WALLET_COUNT);
            phase_bundles.push(build_native_transfer_tx(
                &mut actors,
                wallet_index,
                to_index,
                9_000 + (round as u64 * 17) + (i as u64 * 13),
                STRESS_TX_FEE,
            ));
            counters.native += 1;
            counters.wallet_native += 1;

            let payload = stress_messenger_payload(round, i + 10, &actors[wallet_index].owner_id, 72 + (round + i) % 48);
            phase_bundles.push(build_single_input_payload_tx(&mut actors, wallet_index, payload, &[], STRESS_TX_FEE));
            counters.messenger += 1;
            counters.wallet_messenger += 1;

            let payload = stress_raw_payload(round, i + 20, 96 + (round + i) % 80);
            phase_bundles.push(build_single_input_payload_tx(&mut actors, wallet_index, payload, &[], STRESS_TX_FEE));
            counters.raw_payloads += 1;
            counters.wallet_raw_payloads += 1;
        }

        for i in 0..6 {
            let amount = 10 + (round % 7) as u64 + i as u64;
            let max_supply = 10_000 + amount + (round as u64 * 20) + i as u64;
            let payload = stress_payload_create_asset_with_mint(
                actors[OWNER_INDEX].next_owner_nonce,
                ((round + i) % 4) as u8,
                1,
                max_supply,
                actors[OWNER_INDEX].owner_id,
                actors[OWNER_INDEX].owner_id,
                amount as u128,
                &format!("Owner Stress {round:02} {i:02}"),
                &format!("O{:02}{:02}", round % 100, i),
                b"owner stress asset",
            );
            actors[OWNER_INDEX].next_owner_nonce += 1;
            let bundle = build_single_input_payload_tx(&mut actors, OWNER_INDEX, payload, &[], STRESS_TX_FEE);
            let asset_id = bundle.tx.id().as_bytes();
            created_assets.push(StressAssetExpectation {
                asset_id,
                creator_owner_id: actors[OWNER_INDEX].owner_id,
                mint_authority_owner_id: actors[OWNER_INDEX].owner_id,
                initial_owner_id: actors[OWNER_INDEX].owner_id,
                initial_amount: amount as u128,
            });
            phase_bundles.push(bundle);
            counters.token_creates += 1;
        }

        for i in 0..4 {
            let wallet_index = WALLET_START_INDEX + ((round + i) % STRESS_WALLET_COUNT);
            let amount = 5 + (round % 5) as u64 + i as u64;
            let max_supply = 5_000 + amount + (round as u64 * 10) + i as u64;
            let payload = stress_payload_create_asset_with_mint(
                actors[wallet_index].next_owner_nonce,
                ((round + i) % 3) as u8,
                1,
                max_supply,
                actors[wallet_index].owner_id,
                actors[wallet_index].owner_id,
                amount as u128,
                &format!("Wallet Stress {round:02} {i:02}"),
                &format!("W{:02}{:02}", round % 100, i),
                b"wallet stress asset",
            );
            actors[wallet_index].next_owner_nonce += 1;
            let bundle = build_single_input_payload_tx(&mut actors, wallet_index, payload, &[], STRESS_TX_FEE);
            let asset_id = bundle.tx.id().as_bytes();
            created_assets.push(StressAssetExpectation {
                asset_id,
                creator_owner_id: actors[wallet_index].owner_id,
                mint_authority_owner_id: actors[wallet_index].owner_id,
                initial_owner_id: actors[wallet_index].owner_id,
                initial_amount: amount as u128,
            });
            phase_bundles.push(bundle);
            counters.token_creates += 1;
            counters.wallet_token_creates += 1;
        }

        for i in 0..4 {
            let mint_amount = 70 + (round % 19) as u128 + (i as u128 * 3);
            let payload = stress_payload_mint(base_asset_id, base_asset_nonce, actors[OWNER_INDEX].owner_id, mint_amount);
            base_asset_nonce += 1;
            phase_bundles.push(build_single_input_payload_tx(&mut actors, OWNER_INDEX, payload, &[], STRESS_TX_FEE));
            actors[OWNER_INDEX].expected_base_balance += mint_amount;
            counters.base_ops += 1;

            let recipient_index = WALLET_START_INDEX + ((round + i) % STRESS_WALLET_COUNT);
            let transfer_amount = 11 + ((round + i) % 9) as u128;
            let payload = stress_payload_transfer(base_asset_id, base_asset_nonce, actors[recipient_index].owner_id, transfer_amount);
            base_asset_nonce += 1;
            phase_bundles.push(build_single_input_payload_tx(&mut actors, OWNER_INDEX, payload, &[], STRESS_TX_FEE));
            actors[OWNER_INDEX].expected_base_balance -= transfer_amount;
            actors[recipient_index].expected_base_balance += transfer_amount;
            counters.base_ops += 1;

            let burn_amount = 3 + ((round + i) % 5) as u128;
            let payload = stress_payload_burn(base_asset_id, base_asset_nonce, burn_amount);
            base_asset_nonce += 1;
            phase_bundles.push(build_single_input_payload_tx(&mut actors, OWNER_INDEX, payload, &[], STRESS_TX_FEE));
            actors[OWNER_INDEX].expected_base_balance -= burn_amount;
            counters.base_ops += 1;
        }

        sort_stress_bundles(&mut phase_bundles);
        mine_stress_bundles(&mut ctx, &phase_bundles, &mut next_block_nonce).await;
        record_stress_bundles(&phase_bundles, &mut actors);
        counters.max_block_template_txs = counters.max_block_template_txs.max(phase_bundles.len() + 1);
        counters.mined_stress_blocks += 1;
        if round == 0 {
            log_stress_checkpoint(&ctx, "after_round_0_mixed");
        }

        let state = ctx.consensus.virtual_atomic_state();
        let buy_bundle = build_liquidity_buy_transaction(
            &mut actors,
            OWNER_INDEX,
            &state,
            liquidity_asset_id,
            liquidity_asset_nonce,
            1 + (round % 4) as u128,
        );
        if round == 0 {
            log_stress_bundle("rust round0 buy", &buy_bundle);
        }
        liquidity_asset_nonce += 1;
        mine_stress_bundles(&mut ctx, std::slice::from_ref(&buy_bundle), &mut next_block_nonce).await;
        record_stress_bundles(std::slice::from_ref(&buy_bundle), &mut actors);
        counters.buys += 1;
        counters.max_block_template_txs = counters.max_block_template_txs.max(2);
        counters.mined_stress_blocks += 1;
        if round == 0 {
            log_stress_checkpoint(&ctx, "after_round_0_buy");
            log_liquidity_state(&ctx, "after_round_0_buy", liquidity_asset_id, actors[OWNER_INDEX].owner_id);
        }

        let state = ctx.consensus.virtual_atomic_state();
        let owner_liquidity_balance = stress_balance_of(&state, liquidity_asset_id, actors[OWNER_INDEX].owner_id);
        if owner_liquidity_balance > 0 {
            let token_in = (1 + (round % 2) as u128).min(owner_liquidity_balance);
            let sell_bundle = build_liquidity_sell_transaction(
                &mut actors,
                OWNER_INDEX,
                &state,
                liquidity_asset_id,
                liquidity_asset_nonce,
                token_in,
            );
            liquidity_asset_nonce += 1;
            mine_stress_bundles(&mut ctx, std::slice::from_ref(&sell_bundle), &mut next_block_nonce).await;
            record_stress_bundles(std::slice::from_ref(&sell_bundle), &mut actors);
            counters.sells += 1;
            counters.max_block_template_txs = counters.max_block_template_txs.max(2);
            counters.mined_stress_blocks += 1;
            if round == 0 {
                log_stress_checkpoint(&ctx, "after_round_0_sell");
            }
        }

        if round % 3 == 2 {
            let state = ctx.consensus.virtual_atomic_state();
            if let Some(claim_bundle) =
                build_liquidity_claim_transaction(&mut actors, OWNER_INDEX, &state, liquidity_asset_id, liquidity_asset_nonce)
            {
                liquidity_asset_nonce += 1;
                mine_stress_bundles(&mut ctx, std::slice::from_ref(&claim_bundle), &mut next_block_nonce).await;
                record_stress_bundles(std::slice::from_ref(&claim_bundle), &mut actors);
                counters.claims += 1;
                counters.max_block_template_txs = counters.max_block_template_txs.max(2);
                counters.mined_stress_blocks += 1;
            }
        }
        if round < 3 {
            log_stress_checkpoint(&ctx, &format!("after_round_{round}"));
        }
    }

    mine_stress_block(&mut ctx, Vec::new(), &mut next_block_nonce).await;
    counters.mined_stress_blocks += 1;

    let final_state = ctx.consensus.virtual_atomic_state();
    assert_stress_final_state(
        &ctx,
        &final_state,
        &actors,
        base_asset_id,
        liquidity_asset_id,
        &created_assets,
        base_asset_nonce,
        liquidity_asset_nonce,
        &counters,
        rounds,
    );
}

fn log_stress_bundle(label: &str, bundle: &StressBundle) {
    let inputs: Vec<_> = bundle.tx.inputs.iter().map(|input| input.previous_outpoint.to_string()).collect();
    let outputs: Vec<_> = bundle.tx.outputs.iter().map(|output| output.value).collect();
    eprintln!(
        "{label}: txid={} inputs={:?} outputs={:?} payload={}",
        bundle.tx.id(),
        inputs,
        outputs,
        faster_hex::hex_string(&bundle.tx.payload)
    );
}

fn log_stress_checkpoint(ctx: &TestContext, label: &str) {
    let state = ctx.consensus.virtual_atomic_state();
    let sink = ctx.consensus.get_sink();
    let token_audit_hash = ctx
        .consensus
        .get_atomic_p2p_token_audit_hash(sink)
        .expect("Atomic token audit hash lookup")
        .expect("selected parent must have an Atomic token audit hash");
    let virtual_token_audit_hash = state.p2p_token_audit_hash().expect("virtual Atomic state must be token-auditable");
    eprintln!(
        "rust deterministic atomic stress checkpoint {label}: state_hash={} stored_token_audit_hash={} virtual_token_audit_hash={} sink={}",
        faster_hex::hex_string(&state.canonical_hash()),
        faster_hex::hex_string(&token_audit_hash),
        faster_hex::hex_string(&virtual_token_audit_hash),
        sink
    );
}

fn log_liquidity_state(ctx: &TestContext, label: &str, asset_id: [u8; 32], owner_id: [u8; 32]) {
    let state = ctx.consensus.virtual_atomic_state();
    let asset = state.assets.get(&asset_id).expect("liquidity asset missing for log");
    let pool = asset.liquidity.as_ref().expect("liquidity pool missing for log");
    eprintln!(
        "rust liquidity {label}: total_supply={} owner_balance={} pool_nonce={} curve_version={} curve_mode={} individual_cpay={} individual_token_bps={} real_cpay={} real_token={} virtual_cpay={} virtual_token={} unclaimed_total={} fee_bps={} fee0_version={} fee0_payload={} fee0_unclaimed={} vault_value={} vault_outpoint={} unlock_target={} unlocked={}",
        asset.total_supply,
        stress_balance_of(&state, asset_id, owner_id),
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
        pool.fee_recipients[0].address_version,
        faster_hex::hex_string(&pool.fee_recipients[0].address_payload),
        pool.fee_recipients[0].unclaimed_sompi,
        pool.vault_value_sompi,
        pool.vault_outpoint,
        pool.unlock_target_sompi,
        pool.unlocked
    );
}

fn stress_consensus_config() -> Config {
    ConfigBuilder::new(SIMNET_PARAMS)
        .skip_proof_of_work()
        .enable_sanity_checks()
        .edit_consensus_params(|p| {
            p.coinbase_maturity = 0;
            p.ghostdag_k = 0;
            p.mergeset_size_limit = 1;
            p.max_block_parents = 4;
            p.finality_depth = 2;
            p.pruning_proof_m = 1;
            p.target_time_per_block = 1;
            p.pre_deflationary_phase_base_subsidy = 1_673 * SOMPI_PER_CRYPTIX;
            p.storage_mass_activation_daa_score = u64::MAX;
            p.payload_hf_activation_daa_score = 0;
        })
        .build()
}

fn stress_rounds_from_env() -> usize {
    for key in ["CRYPTIX_RUST_STRESS_ROUNDS", "CRYPTIX_GO_STRESS_ROUNDS"] {
        if let Ok(raw) = env::var(key) {
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                return trimmed.parse::<usize>().unwrap_or_else(|_| panic!("{key} must be a positive integer, got {trimmed:?}"));
            }
        }
    }
    STRESS_DEFAULT_ROUNDS
}

fn stress_actors() -> Vec<StressActor> {
    let mut actors = Vec::with_capacity(WALLET_START_INDEX + STRESS_WALLET_COUNT);
    actors.push(new_stress_actor("owner"));
    actors.push(new_stress_actor("receiver"));
    for i in 0..STRESS_WALLET_COUNT {
        actors.push(new_stress_actor(&format!("wallet-{i:02}")));
    }
    actors
}

fn new_stress_actor(label: &str) -> StressActor {
    let marker = format!("go-atomic-stress:{label}");
    assert!(marker.len() < 76, "stress redeem marker must use single-byte pushdata");
    let mut redeem_script = Vec::with_capacity(marker.len() + 3);
    redeem_script.push(marker.len() as u8);
    redeem_script.extend_from_slice(marker.as_bytes());
    redeem_script.push(0x75);
    redeem_script.push(0x51);
    let script_public_key = cryptix_txscript::pay_to_script_hash_script(&redeem_script);
    let owner_id = atomic_owner_id_from_script(&script_public_key).expect("stress P2SH owner id should derive");
    let recipient_payload = script_public_key.script()[2..34].to_vec();
    StressActor {
        label: label.to_string(),
        redeem_script,
        script_public_key,
        owner_id,
        recipient_payload,
        utxos: Vec::new(),
        next_owner_nonce: 1,
        expected_base_balance: 0,
    }
}

async fn mine_stress_block(ctx: &mut TestContext, txs: Vec<Transaction>, next_block_nonce: &mut u64) -> MutableBlock {
    ctx.simulated_time += 1_000;
    let template = ctx.build_block_template_with_transactions(txs, *next_block_nonce, ctx.simulated_time);
    *next_block_nonce += 1;
    let block = template.block;
    let record_block = block.clone();
    ctx.validate_and_insert_utxo_valid_block(block.to_immutable()).await;
    record_block
}

async fn mine_stress_bundles(ctx: &mut TestContext, bundles: &[StressBundle], next_block_nonce: &mut u64) {
    let txs = bundles.iter().map(|bundle| bundle.tx.clone()).collect();
    mine_stress_block(ctx, txs, next_block_nonce).await;
}

fn build_owner_fanout_transactions(actors: &mut [StressActor]) -> Vec<StressBundle> {
    (0..STRESS_OWNER_FANOUT_INPUTS)
        .map(|_| build_fanout_tx(actors, OWNER_INDEX, OWNER_INDEX, STRESS_FANOUT_OUTPUTS, STRESS_TX_FEE))
        .collect()
}

fn build_wallet_funding_transactions(actors: &mut [StressActor]) -> Vec<StressBundle> {
    (0..STRESS_WALLET_COUNT)
        .map(|i| {
            let wallet_index = WALLET_START_INDEX + i;
            let payments: Vec<_> = (0..STRESS_WALLET_FUNDING_UTXOS)
                .map(|output_index| StressPayment { actor_index: wallet_index, amount: 35_000_000 + output_index as u64 * 10_000 })
                .collect();
            build_single_input_tx_with_payments(actors, OWNER_INDEX, SUBNETWORK_ID_NATIVE, Vec::new(), &payments, STRESS_TX_FEE)
        })
        .collect()
}

fn build_fanout_tx(actors: &mut [StressActor], from_index: usize, to_index: usize, outputs: usize, fee: u64) -> StressBundle {
    let utxo = pop_stress_utxo(actors, from_index, fee + outputs as u64);
    let spendable = utxo.amount - fee;
    let value = spendable / outputs as u64;
    assert!(value > 0, "fanout value for {} is zero", actors[from_index].label);
    let remainder = spendable % outputs as u64;
    let mut tx_outputs = Vec::with_capacity(outputs);
    let mut owners = Vec::with_capacity(outputs);
    for i in 0..outputs {
        let mut amount = value;
        if i == outputs - 1 {
            amount += remainder;
        }
        tx_outputs.push(stress_output(&actors[to_index], amount));
        owners.push(Some(to_index));
    }
    StressBundle { tx: stress_transaction(vec![utxo], tx_outputs, SUBNETWORK_ID_NATIVE, Vec::new()), owners }
}

fn build_native_transfer_tx(actors: &mut [StressActor], from_index: usize, to_index: usize, amount: u64, fee: u64) -> StressBundle {
    build_single_input_tx_with_payments(
        actors,
        from_index,
        SUBNETWORK_ID_NATIVE,
        Vec::new(),
        &[StressPayment { actor_index: to_index, amount }],
        fee,
    )
}

fn build_single_input_payload_tx(
    actors: &mut [StressActor],
    from_index: usize,
    payload: Vec<u8>,
    payments: &[StressPayment],
    fee: u64,
) -> StressBundle {
    build_single_input_tx_with_payments(actors, from_index, SUBNETWORK_ID_PAYLOAD, payload, payments, fee)
}

fn build_single_input_tx_with_payments(
    actors: &mut [StressActor],
    from_index: usize,
    subnetwork_id: SubnetworkId,
    payload: Vec<u8>,
    payments: &[StressPayment],
    fee: u64,
) -> StressBundle {
    let total_payment =
        payments.iter().try_fold(0u64, |total, payment| total.checked_add(payment.amount)).expect("stress payment total overflow");
    let utxo = pop_stress_utxo(actors, from_index, total_payment + fee + 1);
    let change = utxo.amount - total_payment - fee;
    assert!(change > 0, "{} single-input tx would produce zero anchor change", actors[from_index].label);

    let mut tx_outputs = Vec::with_capacity(payments.len() + 1);
    let mut owners = Vec::with_capacity(payments.len() + 1);
    for payment in payments {
        tx_outputs.push(stress_output(&actors[payment.actor_index], payment.amount));
        owners.push(Some(payment.actor_index));
    }
    tx_outputs.push(stress_output(&actors[from_index], change));
    owners.push(Some(from_index));

    StressBundle { tx: stress_transaction(vec![utxo], tx_outputs, subnetwork_id, payload), owners }
}

fn build_create_liquidity_transaction(actors: &mut [StressActor], owner_index: usize, payload: Vec<u8>) -> StressBundle {
    let seed_reserve = SOMPI_PER_CRYPTIX;
    let utxo = pop_stress_utxo(actors, owner_index, seed_reserve + STRESS_TX_FEE + 1);
    let change = utxo.amount - seed_reserve - STRESS_TX_FEE;
    assert!(change > 0, "create-liquidity owner change is zero");
    let tx_outputs = vec![stress_output(&actors[owner_index], change), stress_vault_output(seed_reserve)];
    StressBundle {
        tx: stress_transaction(vec![utxo], tx_outputs, SUBNETWORK_ID_PAYLOAD, payload),
        owners: vec![Some(owner_index), None],
    }
}

fn build_liquidity_buy_transaction(
    actors: &mut [StressActor],
    owner_index: usize,
    state: &AtomicConsensusState,
    asset_id: [u8; 32],
    asset_nonce: u64,
    target_token_out: u128,
) -> StressBundle {
    let pool = stress_liquidity_pool(state, asset_id);
    let spendable = pool.real_token_reserves.checked_sub(1).expect("liquidity real token reserves underflow");
    assert!(spendable > 0, "liquidity pool has no spendable real token reserves");
    let target_token_out = target_token_out.min(spendable);
    let cpay_in = stress_min_gross_input_for_token_out(
        pool.real_token_reserves,
        pool.virtual_cpay_reserves_sompi,
        pool.virtual_token_reserves,
        target_token_out,
        pool.fee_bps,
    );
    let utxo = pop_stress_utxo(actors, owner_index, cpay_in + STRESS_TX_FEE + 1);
    let change = utxo.amount - cpay_in - STRESS_TX_FEE;
    let vault_utxo = stress_vault_utxo(&pool);
    let tx_outputs = vec![stress_output(&actors[owner_index], change), stress_vault_output(pool.vault_value_sompi + cpay_in)];
    StressBundle {
        tx: stress_transaction(
            vec![utxo, vault_utxo],
            tx_outputs,
            SUBNETWORK_ID_PAYLOAD,
            stress_payload_buy_liquidity(asset_id, asset_nonce, pool.pool_nonce, cpay_in, target_token_out),
        ),
        owners: vec![Some(owner_index), None],
    }
}

fn build_liquidity_sell_transaction(
    actors: &mut [StressActor],
    owner_index: usize,
    state: &AtomicConsensusState,
    asset_id: [u8; 32],
    asset_nonce: u64,
    token_in: u128,
) -> StressBundle {
    let pool = stress_liquidity_pool(state, asset_id);
    let gross_out =
        stress_cpmm_sell(pool.real_cpay_reserves_sompi, pool.virtual_cpay_reserves_sompi, pool.virtual_token_reserves, token_in);
    let cpay_out = gross_out - stress_fee(gross_out, pool.fee_bps);
    assert!(cpay_out > 0, "sell cpay_out is zero");
    let utxo = pop_stress_utxo(actors, owner_index, STRESS_TX_FEE + 1);
    let change = utxo.amount - STRESS_TX_FEE;
    let vault_utxo = stress_vault_utxo(&pool);
    assert!(pool.vault_value_sompi > cpay_out, "sell would drain vault");
    let tx_outputs = vec![
        stress_output(&actors[owner_index], cpay_out),
        stress_vault_output(pool.vault_value_sompi - cpay_out),
        stress_output(&actors[owner_index], change),
    ];
    StressBundle {
        tx: stress_transaction(
            vec![utxo, vault_utxo],
            tx_outputs,
            SUBNETWORK_ID_PAYLOAD,
            stress_payload_sell_liquidity(asset_id, asset_nonce, pool.pool_nonce, token_in, cpay_out, 0),
        ),
        owners: vec![Some(owner_index), None, Some(owner_index)],
    }
}

fn build_liquidity_claim_transaction(
    actors: &mut [StressActor],
    owner_index: usize,
    state: &AtomicConsensusState,
    asset_id: [u8; 32],
    asset_nonce: u64,
) -> Option<StressBundle> {
    let pool = stress_liquidity_pool(state, asset_id);
    assert_eq!(pool.fee_recipients.len(), 1, "liquidity fee recipient count mismatch");
    assert_eq!(pool.fee_recipients[0].owner_id, actors[owner_index].owner_id, "liquidity fee recipient mismatch");
    let unclaimed = pool.fee_recipients[0].unclaimed_sompi;
    if unclaimed == 0 {
        return None;
    }
    let claim_amount = unclaimed.min(250_000);
    let utxo = pop_stress_utxo(actors, owner_index, STRESS_TX_FEE + 1);
    let change = utxo.amount - STRESS_TX_FEE;
    let vault_utxo = stress_vault_utxo(&pool);
    assert!(pool.vault_value_sompi > claim_amount, "claim would drain vault");
    let tx_outputs = vec![
        stress_output(&actors[owner_index], claim_amount),
        stress_vault_output(pool.vault_value_sompi - claim_amount),
        stress_output(&actors[owner_index], change),
    ];
    Some(StressBundle {
        tx: stress_transaction(
            vec![utxo, vault_utxo],
            tx_outputs,
            SUBNETWORK_ID_PAYLOAD,
            stress_payload_claim_liquidity(asset_id, asset_nonce, pool.pool_nonce, 0, claim_amount, 0),
        ),
        owners: vec![Some(owner_index), None, Some(owner_index)],
    })
}

fn stress_transaction(
    utxos: Vec<StressUtxo>,
    outputs: Vec<TransactionOutput>,
    subnetwork_id: SubnetworkId,
    payload: Vec<u8>,
) -> Transaction {
    let inputs = utxos.iter().map(stress_input).collect();
    Transaction::new(TX_VERSION, inputs, outputs, 0, subnetwork_id, 0, payload)
}

fn stress_input(utxo: &StressUtxo) -> TransactionInput {
    let signature_script = if utxo.redeem_script.is_empty() {
        Vec::new()
    } else {
        cryptix_txscript::pay_to_script_hash_signature_script(utxo.redeem_script.clone(), vec![]).unwrap()
    };
    TransactionInput::new(utxo.outpoint, signature_script, MAX_TX_IN_SEQUENCE_NUM, 0)
}

fn stress_output(actor: &StressActor, amount: u64) -> TransactionOutput {
    assert!(amount > 0, "zero-value stress output");
    TransactionOutput::new(amount, actor.script_public_key.clone())
}

fn stress_vault_output(amount: u64) -> TransactionOutput {
    assert!(amount > 0, "zero-value liquidity vault output");
    TransactionOutput::new(amount, stress_liquidity_vault_script())
}

fn stress_liquidity_vault_script() -> ScriptPublicKey {
    ScriptPublicKey::new(0, ScriptVec::from_slice(&[0x04, b'C', b'L', b'V', b'1', 0x75, 0x51]))
}

fn stress_vault_utxo(pool: &AtomicLiquidityPoolState) -> StressUtxo {
    StressUtxo { outpoint: pool.vault_outpoint, amount: pool.vault_value_sompi, redeem_script: Vec::new() }
}

fn pop_stress_utxo(actors: &mut [StressActor], actor_index: usize, min_amount: u64) -> StressUtxo {
    if let Some(position) = actors[actor_index].utxos.iter().position(|utxo| utxo.amount >= min_amount) {
        return actors[actor_index].utxos.remove(position);
    }
    let total: u64 = actors[actor_index].utxos.iter().map(|utxo| utxo.amount).sum();
    panic!("{} has no UTXO >= {}; count={} total={}", actors[actor_index].label, min_amount, actors[actor_index].utxos.len(), total);
}

fn record_coinbase_outputs(block: &MutableBlock, actors: &mut [StressActor], actor_index: usize) {
    let coinbase = block.transactions.first().expect("block has no coinbase transaction");
    record_transaction_outputs(coinbase, &[Some(actor_index)], actors);
}

fn record_stress_bundles(bundles: &[StressBundle], actors: &mut [StressActor]) {
    for bundle in bundles {
        record_transaction_outputs(&bundle.tx, &bundle.owners, actors);
    }
}

fn record_transaction_outputs(tx: &Transaction, owners: &[Option<usize>], actors: &mut [StressActor]) {
    let tx_id = tx.id();
    for (index, owner_index) in owners.iter().enumerate() {
        let Some(owner_index) = owner_index else { continue };
        if index >= tx.outputs.len() {
            continue;
        }
        let redeem_script = actors[*owner_index].redeem_script.clone();
        actors[*owner_index].utxos.push(StressUtxo {
            outpoint: TransactionOutpoint::new(tx_id, index as u32),
            amount: tx.outputs[index].value,
            redeem_script,
        });
    }
}

fn sort_stress_bundles(bundles: &mut [StressBundle]) {
    bundles.sort_by(|left, right| stress_subnetwork_rank(&left.tx).cmp(&stress_subnetwork_rank(&right.tx)));
}

fn stress_subnetwork_rank(tx: &Transaction) -> u8 {
    if tx.subnetwork_id == SUBNETWORK_ID_NATIVE {
        0
    } else {
        1
    }
}

fn assert_stress_final_state(
    ctx: &TestContext,
    state: &AtomicConsensusState,
    actors: &[StressActor],
    base_asset_id: [u8; 32],
    liquidity_asset_id: [u8; 32],
    created_assets: &[StressAssetExpectation],
    base_asset_nonce: u64,
    liquidity_asset_nonce: u64,
    counters: &StressCounters,
    rounds: usize,
) {
    state.validate_normalized().expect("final Atomic state must be normalized");
    let selected_parent = ctx.consensus.get_sink();
    let stored_hash = ctx.consensus.atomic_root_record_hash_for_tests(selected_parent);
    let calculated_hash = state.canonical_hash();
    assert_eq!(stored_hash, calculated_hash, "stored Atomic state hash mismatch");
    assert_eq!(
        ctx.consensus.selected_chain_atomic_hash_from_deltas_for_tests(selected_parent),
        calculated_hash,
        "selected-chain Atomic delta replay mismatch"
    );
    let token_audit_hash = ctx
        .consensus
        .get_atomic_p2p_token_audit_hash(selected_parent)
        .expect("Atomic token audit hash lookup")
        .expect("selected parent must have an Atomic token audit hash");

    if let Some(expected) = stress_expected_env("CRYPTIX_RUST_STRESS_EXPECTED_HASH", "CRYPTIX_GO_STRESS_EXPECTED_HASH")
        .or_else(|| (rounds == STRESS_DEFAULT_ROUNDS).then(|| STRESS_EXPECTED_STATE_HASH.to_string()))
    {
        assert_eq!(
            faster_hex::hex_string(&calculated_hash),
            expected.to_ascii_lowercase(),
            "final Atomic hash mismatch against expected cross-check hash"
        );
    }
    if let Some(expected) = stress_expected_env("CRYPTIX_RUST_STRESS_EXPECTED_TOKEN_HASH", "CRYPTIX_GO_STRESS_EXPECTED_TOKEN_HASH")
        .or_else(|| (rounds == STRESS_DEFAULT_ROUNDS).then(|| STRESS_EXPECTED_TOKEN_AUDIT_HASH.to_string()))
    {
        assert_eq!(
            faster_hex::hex_string(&token_audit_hash),
            expected.to_ascii_lowercase(),
            "final Atomic token audit hash mismatch against expected cross-check hash"
        );
    }

    assert!(counters.max_block_template_txs >= 50, "stress never built a large mixed block");
    assert!(counters.buys > 0 && counters.sells > 0 && counters.claims > 0, "liquidity buy/sell/claim coverage missing");
    assert!(
        counters.wallet_native > 0
            && counters.wallet_messenger > 0
            && counters.wallet_raw_payloads > 0
            && counters.wallet_token_creates > 0,
        "wallet transaction diversity missing"
    );

    let base_asset = state.assets.get(&base_asset_id).expect("base asset missing from Atomic state");
    let expected_base_supply: u128 = actors.iter().map(|actor| actor.expected_base_balance).sum();
    assert_eq!(base_asset.total_supply, expected_base_supply, "base asset total supply mismatch");
    for actor in actors {
        assert_stress_balance(state, base_asset_id, actor.owner_id, actor.expected_base_balance, &actor.label);
    }

    assert_eq!(
        state.next_nonces.get(&AtomicNonceKey::owner(actors[OWNER_INDEX].owner_id)).copied().unwrap_or(0),
        actors[OWNER_INDEX].next_owner_nonce,
        "owner nonce mismatch"
    );
    assert_eq!(
        state.next_nonces.get(&AtomicNonceKey::asset(actors[OWNER_INDEX].owner_id, base_asset_id)).copied().unwrap_or(0),
        base_asset_nonce,
        "base asset nonce mismatch"
    );
    assert_eq!(
        state.next_nonces.get(&AtomicNonceKey::asset(actors[OWNER_INDEX].owner_id, liquidity_asset_id)).copied().unwrap_or(0),
        liquidity_asset_nonce,
        "liquidity asset nonce mismatch"
    );
    for actor in actors.iter().skip(WALLET_START_INDEX) {
        assert_eq!(
            state.next_nonces.get(&AtomicNonceKey::owner(actor.owner_id)).copied().unwrap_or(0),
            actor.next_owner_nonce,
            "{} owner nonce mismatch",
            actor.label
        );
        assert!(state.anchor_counts.get(&actor.owner_id).copied().unwrap_or(0) > 0, "{} lost all Atomic owner anchors", actor.label);
    }
    assert!(state.anchor_counts.get(&actors[OWNER_INDEX].owner_id).copied().unwrap_or(0) > 0, "owner lost all Atomic anchors");

    for expected in created_assets {
        let asset = state
            .assets
            .get(&expected.asset_id)
            .unwrap_or_else(|| panic!("created asset {} missing", faster_hex::hex_string(&expected.asset_id)));
        assert_eq!(asset.asset_class, AtomicAssetClass::Standard, "created asset class mismatch");
        assert_eq!(asset.creator_owner_id, expected.creator_owner_id, "created asset creator mismatch");
        assert_eq!(asset.mint_authority_owner_id, expected.mint_authority_owner_id, "created asset mint authority mismatch");
        assert_eq!(asset.total_supply, expected.initial_amount, "created asset total supply mismatch");
        assert_stress_balance(state, expected.asset_id, expected.initial_owner_id, expected.initial_amount, "created asset initial");
    }

    let liquidity_asset = state.assets.get(&liquidity_asset_id).expect("liquidity asset missing");
    let pool = liquidity_asset.liquidity.as_ref().expect("liquidity pool missing");
    assert_eq!(liquidity_asset.asset_class, AtomicAssetClass::Liquidity, "liquidity asset class mismatch");
    assert_eq!(liquidity_asset.creator_owner_id, actors[OWNER_INDEX].owner_id, "liquidity creator mismatch");
    assert_eq!(pool.fee_recipients.len(), 1, "liquidity fee recipient count mismatch");
    assert_eq!(pool.fee_recipients[0].owner_id, actors[OWNER_INDEX].owner_id, "liquidity fee recipient mismatch");
    assert!(pool.pool_nonce > 1, "liquidity pool nonce did not advance");
    assert_eq!(
        pool.vault_value_sompi,
        pool.real_cpay_reserves_sompi + pool.unclaimed_fee_total_sompi,
        "liquidity vault value mismatch"
    );
    assert_eq!(
        liquidity_asset.total_supply + pool.real_token_reserves,
        liquidity_asset.max_supply,
        "liquidity supply invariant mismatch"
    );
    assert!(state.liquidity_vault_outpoints.contains_key(&pool.vault_outpoint), "liquidity vault outpoint index missing");

    eprintln!(
        "rust deterministic atomic stress summary: rounds={} wallets={} active_wallets={} native={} wallet_native={} messenger={} wallet_messenger={} raw_payloads={} wallet_raw_payloads={} token_creates={} wallet_token_creates={} base_ops={} buys={} sells={} claims={} max_block_template_txs={} mined_stress_blocks={} state_hash={}",
        rounds,
        STRESS_WALLET_COUNT,
        actors.iter().skip(WALLET_START_INDEX).filter(|actor| !actor.utxos.is_empty()).count(),
        counters.native,
        counters.wallet_native,
        counters.messenger,
        counters.wallet_messenger,
        counters.raw_payloads,
        counters.wallet_raw_payloads,
        counters.token_creates,
        counters.wallet_token_creates,
        counters.base_ops,
        counters.buys,
        counters.sells,
        counters.claims,
        counters.max_block_template_txs,
        counters.mined_stress_blocks,
        faster_hex::hex_string(&calculated_hash)
    );
    eprintln!("rust deterministic atomic stress token_audit_hash={}", faster_hex::hex_string(&token_audit_hash));
}

fn stress_expected_env(primary: &str, fallback: &str) -> Option<String> {
    env::var(primary).ok().or_else(|| env::var(fallback).ok()).map(|value| value.trim().to_string()).filter(|value| !value.is_empty())
}

fn assert_stress_balance(state: &AtomicConsensusState, asset_id: [u8; 32], owner_id: [u8; 32], expected: u128, label: &str) {
    let got = stress_balance_of(state, asset_id, owner_id);
    assert_eq!(got, expected, "{label} balance mismatch");
}

fn stress_balance_of(state: &AtomicConsensusState, asset_id: [u8; 32], owner_id: [u8; 32]) -> u128 {
    state.balances.get(&AtomicBalanceKey { asset_id, owner_id }).copied().unwrap_or(0)
}

fn stress_liquidity_pool(state: &AtomicConsensusState, asset_id: [u8; 32]) -> AtomicLiquidityPoolState {
    state
        .assets
        .get(&asset_id)
        .unwrap_or_else(|| panic!("liquidity asset {} missing", faster_hex::hex_string(&asset_id)))
        .liquidity
        .clone()
        .expect("liquidity pool missing")
}

fn stress_payload_header(opcode: u8, nonce: u64) -> Vec<u8> {
    let mut payload = Vec::with_capacity(16);
    payload.extend_from_slice(b"CAT");
    payload.push(1);
    payload.push(opcode);
    payload.push(0);
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&nonce.to_le_bytes());
    payload
}

fn stress_payload_create_asset_with_mint(
    nonce: u64,
    decimals: u8,
    supply_mode: u8,
    max_supply: u64,
    mint_authority_owner_id: [u8; 32],
    initial_owner_id: [u8; 32],
    initial_amount: u128,
    name: &str,
    symbol: &str,
    metadata: &[u8],
) -> Vec<u8> {
    let mut payload = stress_payload_header(4, nonce);
    payload.push(1);
    payload.push(decimals);
    payload.push(supply_mode);
    payload.extend_from_slice(&(max_supply as u128).to_le_bytes());
    payload.extend_from_slice(&mint_authority_owner_id);
    append_stress_string_fields(&mut payload, name.as_bytes(), symbol.as_bytes(), metadata);
    payload.extend_from_slice(&initial_amount.to_le_bytes());
    payload.extend_from_slice(&initial_owner_id);
    payload
}

fn stress_payload_create_liquidity(
    nonce: u64,
    max_supply: u64,
    recipient_payload: &[u8],
    name: &str,
    symbol: &str,
    metadata: &[u8],
) -> Vec<u8> {
    let mut payload = stress_payload_header(5, nonce);
    payload.push(1);
    payload.push(1);
    payload.push(0);
    payload.extend_from_slice(&(max_supply as u128).to_le_bytes());
    append_stress_string_fields(&mut payload, name.as_bytes(), symbol.as_bytes(), metadata);
    payload.extend_from_slice(&SOMPI_PER_CRYPTIX.to_le_bytes());
    payload.extend_from_slice(&100u16.to_le_bytes());
    payload.push(1);
    payload.push(8);
    payload.extend_from_slice(recipient_payload);
    payload.extend_from_slice(&0u64.to_le_bytes());
    payload.extend_from_slice(&0u128.to_le_bytes());
    payload
}

fn stress_payload_transfer(asset_id: [u8; 32], nonce: u64, to_owner_id: [u8; 32], amount: u128) -> Vec<u8> {
    let mut payload = stress_payload_header(1, nonce);
    payload.extend_from_slice(&asset_id);
    payload.extend_from_slice(&to_owner_id);
    payload.extend_from_slice(&amount.to_le_bytes());
    payload
}

fn stress_payload_mint(asset_id: [u8; 32], nonce: u64, to_owner_id: [u8; 32], amount: u128) -> Vec<u8> {
    let mut payload = stress_payload_header(2, nonce);
    payload.extend_from_slice(&asset_id);
    payload.extend_from_slice(&to_owner_id);
    payload.extend_from_slice(&amount.to_le_bytes());
    payload
}

fn stress_payload_burn(asset_id: [u8; 32], nonce: u64, amount: u128) -> Vec<u8> {
    let mut payload = stress_payload_header(3, nonce);
    payload.extend_from_slice(&asset_id);
    payload.extend_from_slice(&amount.to_le_bytes());
    payload
}

fn stress_payload_buy_liquidity(
    asset_id: [u8; 32],
    nonce: u64,
    expected_pool_nonce: u64,
    cpay_in: u64,
    min_token_out: u128,
) -> Vec<u8> {
    let mut payload = stress_payload_header(6, nonce);
    payload.extend_from_slice(&asset_id);
    payload.extend_from_slice(&expected_pool_nonce.to_le_bytes());
    payload.extend_from_slice(&cpay_in.to_le_bytes());
    payload.extend_from_slice(&min_token_out.to_le_bytes());
    payload
}

fn stress_payload_sell_liquidity(
    asset_id: [u8; 32],
    nonce: u64,
    expected_pool_nonce: u64,
    token_in: u128,
    min_cpay_out: u64,
    receive_output_index: u16,
) -> Vec<u8> {
    let mut payload = stress_payload_header(7, nonce);
    payload.extend_from_slice(&asset_id);
    payload.extend_from_slice(&expected_pool_nonce.to_le_bytes());
    payload.extend_from_slice(&token_in.to_le_bytes());
    payload.extend_from_slice(&min_cpay_out.to_le_bytes());
    payload.extend_from_slice(&receive_output_index.to_le_bytes());
    payload
}

fn stress_payload_claim_liquidity(
    asset_id: [u8; 32],
    nonce: u64,
    expected_pool_nonce: u64,
    recipient_index: u8,
    claim_amount: u64,
    receive_output_index: u16,
) -> Vec<u8> {
    let mut payload = stress_payload_header(8, nonce);
    payload.extend_from_slice(&asset_id);
    payload.extend_from_slice(&expected_pool_nonce.to_le_bytes());
    payload.push(recipient_index);
    payload.extend_from_slice(&claim_amount.to_le_bytes());
    payload.extend_from_slice(&receive_output_index.to_le_bytes());
    payload
}

fn append_stress_string_fields(payload: &mut Vec<u8>, name: &[u8], symbol: &[u8], metadata: &[u8]) {
    assert!(name.len() <= 32 && symbol.len() <= 10 && metadata.len() <= 256, "CAT string field too long");
    payload.push(name.len() as u8);
    payload.push(symbol.len() as u8);
    payload.extend_from_slice(&(metadata.len() as u16).to_le_bytes());
    payload.extend_from_slice(name);
    payload.extend_from_slice(symbol);
    payload.extend_from_slice(metadata);
}

fn stress_messenger_payload(round: usize, slot: usize, owner_id: &[u8; 32], length: usize) -> Vec<u8> {
    let mut payload = format!("CXM:go-stress:{round:04}:{slot:02}:").into_bytes();
    payload.extend_from_slice(&owner_id[..8]);
    while payload.len() < length {
        payload.push(b'a' + ((round + slot + payload.len()) % 26) as u8);
    }
    payload
}

fn stress_raw_payload(round: usize, slot: usize, length: usize) -> Vec<u8> {
    let mut payload = format!("RAW:go-stress:{round:04}:{slot:02}:").into_bytes();
    while payload.len() < length {
        payload.push(((round * 31 + slot * 17 + payload.len()) & 0xff) as u8);
    }
    payload
}

fn stress_fee(amount: u64, fee_bps: u16) -> u64 {
    (u128::from(amount) * u128::from(fee_bps) / 10_000) as u64
}

fn stress_ceil_div(numerator: u128, denominator: u128) -> u128 {
    assert!(denominator > 0, "division by zero");
    numerator / denominator + u128::from(numerator % denominator != 0)
}

fn stress_min_gross_input_for_token_out(
    real_token_reserves: u128,
    virtual_cpay_reserves: u64,
    virtual_token_reserves: u128,
    token_out: u128,
    fee_bps: u16,
) -> u64 {
    assert!(token_out > 0, "canonical buy target token_out is invalid");
    let spendable_tokens = real_token_reserves.checked_sub(1).expect("real token reserves underflow");
    assert!(token_out <= spendable_tokens, "canonical buy token_out drains final token");
    let y_after = virtual_token_reserves - token_out;
    let x_before = u128::from(virtual_cpay_reserves);
    let x_after = stress_ceil_div(x_before * virtual_token_reserves, y_after);
    assert!(x_after > x_before, "canonical buy produced zero net input");
    let gross_in = stress_min_gross_input_for_net_input(u64::try_from(x_after - x_before).unwrap(), fee_bps);
    let actual_token_out =
        stress_cpmm_buy(real_token_reserves, virtual_cpay_reserves, virtual_token_reserves, gross_in - stress_fee(gross_in, fee_bps));
    assert!(actual_token_out >= token_out, "canonical buy verification failed");
    gross_in
}

fn stress_min_gross_input_for_net_input(net_in: u64, fee_bps: u16) -> u64 {
    assert!(net_in > 0 && fee_bps < 10_000, "canonical buy net input or fee bps is invalid");
    if fee_bps == 0 {
        return net_in;
    }
    let fee_denominator = 10_000u128 - u128::from(fee_bps);
    let mut gross_in = u64::try_from(((u128::from(net_in) - 1) * 10_000) / fee_denominator + 1).unwrap();
    while gross_in > 1 {
        let previous = gross_in - 1;
        if previous - stress_fee(previous, fee_bps) < net_in {
            break;
        }
        gross_in = previous;
    }
    loop {
        if gross_in - stress_fee(gross_in, fee_bps) >= net_in {
            break;
        }
        gross_in = gross_in.checked_add(1).expect("canonical buy gross input overflow");
    }
    gross_in
}

fn stress_cpmm_buy(real_token_reserves: u128, virtual_cpay_reserves: u64, virtual_token_reserves: u128, cpay_net_in: u64) -> u128 {
    assert!(cpay_net_in > 0, "CPMM buy net input cannot be zero");
    let spendable_tokens = real_token_reserves.checked_sub(1).expect("CPMM buy reserve underflow");
    assert!(spendable_tokens > 0, "CPMM buy real token reserve floor reached");
    let x_after = virtual_cpay_reserves.checked_add(cpay_net_in).expect("CPMM x_after overflow");
    let y_after = stress_ceil_div(u128::from(virtual_cpay_reserves) * virtual_token_reserves, u128::from(x_after));
    let token_out = virtual_token_reserves - y_after;
    assert!(token_out > 0 && token_out <= spendable_tokens, "CPMM buy token_out invalid");
    token_out
}

fn stress_cpmm_sell(real_cpay_reserves: u64, virtual_cpay_reserves: u64, virtual_token_reserves: u128, token_in: u128) -> u64 {
    assert!(token_in > 0, "CPMM sell token input cannot be zero");
    let y_after = virtual_token_reserves.checked_add(token_in).expect("CPMM y_after overflow");
    let x_after = stress_ceil_div(u128::from(virtual_cpay_reserves) * virtual_token_reserves, y_after);
    let x_after = u64::try_from(x_after).expect("CPMM sell x_after does not fit u64");
    assert!(x_after <= virtual_cpay_reserves, "CPMM sell x_after exceeds x_before");
    let gross_out = virtual_cpay_reserves - x_after;
    assert!(gross_out > 0, "CPMM sell produced zero gross_out");
    assert!(gross_out <= real_cpay_reserves - 1, "CPMM sell would drain final real sompi");
    gross_out
}
