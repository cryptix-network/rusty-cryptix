use crate::common::{
    daemon::Daemon,
    utils::{fetch_spendable_utxos, required_fee, wait_for},
};
use blake2b_simd::Params as Blake2bParams;
use cryptix_addresses::{Address, Version};
use cryptix_consensus::params::SIMNET_PARAMS;
use cryptix_consensus_core::{
    constants::{SOMPI_PER_CRYPTIX, TX_VERSION},
    header::Header,
    sign::{sign, sign_with_multiple_v2},
    subnets::{SUBNETWORK_ID_NATIVE, SUBNETWORK_ID_PAYLOAD},
    tx::{
        MutableTransaction, ScriptPublicKey, ScriptVec, Transaction, TransactionId, TransactionInput, TransactionOutpoint,
        TransactionOutput, UtxoEntry,
    },
};
use cryptix_consensusmanager::ConsensusManager;
use cryptix_grpc_client::GrpcClient;
use cryptix_rpc_core::{api::rpc::RpcApi, model::*};
use cryptix_txscript::pay_to_address_script;
use cryptixd_lib::args::Args;
use rand::thread_rng;
use secp256k1::Keypair;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};

const CAT_OWNER_DOMAIN: &[u8] = b"CAT_OWNER_V2";
const CURRENT_TOKEN_VERSION: u8 = 1;
const CURRENT_LIQUIDITY_CURVE_VERSION: u8 = 1;
const LIQUIDITY_TOKEN_SUPPLY_RAW: u128 = 1_000_000;
const MIN_LIQUIDITY_SEED_RESERVE_SOMPI: u64 = SOMPI_PER_CRYPTIX;
const OWNER_AUTH_SCHEME_PUBKEY: u8 = 0;
const OWNER_AUTH_SCHEME_PUBKEY_ECDSA: u8 = 1;
const ATOMIC_TEST_PAYLOAD_HF_DAA: u64 = 2;
const ATOMIC_LONG_STRESS_DEFAULT_SECONDS: u64 = 300;
const ATOMIC_LONG_STRESS_INDEX_WAIT_ATTEMPTS: usize = 1_800;
const ATOMIC_LONG_STRESS_WALLET_COUNT: usize = 8;
const ATOMIC_LONG_STRESS_WALLET_FUNDING_OUTPUTS: usize = 12;
const ATOMIC_LONG_STRESS_WALLET_MIN_UTXOS: usize = 16;
const ATOMIC_LONG_STRESS_WALLET_TOKEN_CREATES_PER_ROUND: u64 = 4;
const ATOMIC_REORG_STRESS_DEFAULT_ROUNDS: u64 = 8;
const ATOMIC_REORG_STRESS_WALLET_COUNT: usize = 4;
const TOKEN_EVENTS_RPC_PAGE_LIMIT: u32 = 4_096;

fn owner_id_from_address(address: &Address) -> [u8; 32] {
    let (scheme, canonical_pubkey_bytes) = match address.version {
        Version::PubKey => (OWNER_AUTH_SCHEME_PUBKEY, address.payload.as_slice()),
        Version::PubKeyECDSA => (OWNER_AUTH_SCHEME_PUBKEY_ECDSA, address.payload.as_slice()),
        other => panic!("unsupported owner address version for tests: {other:?}"),
    };
    let pubkey_len = u16::try_from(canonical_pubkey_bytes.len()).expect("pubkey length");

    let mut hasher = Blake2bParams::new().hash_length(32).to_state();
    hasher.update(CAT_OWNER_DOMAIN);
    hasher.update(&[scheme]);
    hasher.update(&pubkey_len.to_le_bytes());
    hasher.update(canonical_pubkey_bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_bytes());
    out
}

fn hex32(bytes: [u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn base_header(op: u8, auth_input_index: u16, nonce: u64) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"CAT");
    payload.push(1);
    payload.push(op);
    payload.push(0);
    payload.extend_from_slice(&auth_input_index.to_le_bytes());
    payload.extend_from_slice(&nonce.to_le_bytes());
    payload
}

fn payload_create_asset(
    auth_input_index: u16,
    nonce: u64,
    decimals: u8,
    mint_authority_owner_id: [u8; 32],
    name: &[u8],
    symbol: &[u8],
    metadata: &[u8],
) -> Vec<u8> {
    let mut payload = base_header(0, auth_input_index, nonce);
    payload.push(CURRENT_TOKEN_VERSION);
    payload.push(decimals);
    payload.push(0);
    payload.extend_from_slice(&0u128.to_le_bytes());
    payload.extend_from_slice(&mint_authority_owner_id);
    payload.push(name.len() as u8);
    payload.push(symbol.len() as u8);
    payload.extend_from_slice(&(metadata.len() as u16).to_le_bytes());
    payload.extend_from_slice(name);
    payload.extend_from_slice(symbol);
    payload.extend_from_slice(metadata);
    payload
}

fn payload_mint(auth_input_index: u16, nonce: u64, asset_id: [u8; 32], to_owner_id: [u8; 32], amount: u128) -> Vec<u8> {
    let mut payload = base_header(2, auth_input_index, nonce);
    payload.extend_from_slice(&asset_id);
    payload.extend_from_slice(&to_owner_id);
    payload.extend_from_slice(&amount.to_le_bytes());
    payload
}

fn payload_transfer(auth_input_index: u16, nonce: u64, asset_id: [u8; 32], to_owner_id: [u8; 32], amount: u128) -> Vec<u8> {
    let mut payload = base_header(1, auth_input_index, nonce);
    payload.extend_from_slice(&asset_id);
    payload.extend_from_slice(&to_owner_id);
    payload.extend_from_slice(&amount.to_le_bytes());
    payload
}

fn payload_burn(auth_input_index: u16, nonce: u64, asset_id: [u8; 32], amount: u128) -> Vec<u8> {
    let mut payload = base_header(3, auth_input_index, nonce);
    payload.extend_from_slice(&asset_id);
    payload.extend_from_slice(&amount.to_le_bytes());
    payload
}

fn payload_create_asset_with_mint(
    auth_input_index: u16,
    nonce: u64,
    decimals: u8,
    max_supply: u128,
    mint_authority_owner_id: [u8; 32],
    initial_mint_to_owner_id: [u8; 32],
    initial_mint_amount: u128,
    name: &[u8],
    symbol: &[u8],
    metadata: &[u8],
) -> Vec<u8> {
    let mut payload = base_header(4, auth_input_index, nonce);
    payload.push(CURRENT_TOKEN_VERSION);
    payload.push(decimals);
    payload.push(1);
    payload.extend_from_slice(&max_supply.to_le_bytes());
    payload.extend_from_slice(&mint_authority_owner_id);
    payload.push(name.len() as u8);
    payload.push(symbol.len() as u8);
    payload.extend_from_slice(&(metadata.len() as u16).to_le_bytes());
    payload.extend_from_slice(name);
    payload.extend_from_slice(symbol);
    payload.extend_from_slice(metadata);
    payload.extend_from_slice(&initial_mint_amount.to_le_bytes());
    payload.extend_from_slice(&initial_mint_to_owner_id);
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
    let mut payload = base_header(6, auth_input_index, nonce);
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
    let mut payload = base_header(7, auth_input_index, nonce);
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
    let mut payload = base_header(8, auth_input_index, nonce);
    payload.extend_from_slice(&asset_id);
    payload.extend_from_slice(&expected_pool_nonce.to_le_bytes());
    payload.push(recipient_index);
    payload.extend_from_slice(&claim_amount_sompi.to_le_bytes());
    payload.extend_from_slice(&claim_receive_output_index.to_le_bytes());
    payload
}

fn payload_create_liquidity_with_fee_recipient(
    auth_input_index: u16,
    nonce: u64,
    max_supply: u128,
    fee_bps: u16,
    recipient_address: &Address,
    launch_buy_sompi: u64,
    launch_buy_min_token_out: u128,
    name: &[u8],
    symbol: &[u8],
) -> Vec<u8> {
    let mut payload = base_header(5, auth_input_index, nonce);
    payload.push(CURRENT_TOKEN_VERSION);
    payload.push(CURRENT_LIQUIDITY_CURVE_VERSION);
    payload.push(0);
    payload.extend_from_slice(&max_supply.to_le_bytes());
    payload.push(name.len() as u8);
    payload.push(symbol.len() as u8);
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(name);
    payload.extend_from_slice(symbol);
    payload.extend_from_slice(&MIN_LIQUIDITY_SEED_RESERVE_SOMPI.to_le_bytes());
    payload.extend_from_slice(&fee_bps.to_le_bytes());
    payload.push(1);
    let recipient_version = match recipient_address.version {
        Version::PubKey => 0,
        Version::PubKeyECDSA => 1,
        other => panic!("unsupported liquidity fee recipient version for tests: {other:?}"),
    };
    payload.push(recipient_version);
    payload.extend_from_slice(recipient_address.payload.as_slice());
    payload.extend_from_slice(&launch_buy_sompi.to_le_bytes());
    payload.extend_from_slice(&launch_buy_min_token_out.to_le_bytes());
    payload
}

fn liquidity_vault_script() -> ScriptPublicKey {
    ScriptPublicKey::new(0, ScriptVec::from_slice(&[0x04, b'C', b'L', b'V', b'1', 0x75, 0x51]))
}

fn messenger_payload_v1(sequence: u64, sender_pubkey: [u8; 32], body_len: usize) -> Vec<u8> {
    assert!(body_len <= 1_968, "Messenger v1 body would exceed the 2048 byte payload limit");
    let mut payload = Vec::with_capacity(80 + body_len);
    payload.extend_from_slice(b"CXM");
    payload.push(1);
    payload.push(1 + (sequence % 4) as u8);
    payload.push((sequence % 2) as u8);

    let mut recipient_tag = [0u8; 16];
    recipient_tag[..8].copy_from_slice(&sequence.to_le_bytes());
    recipient_tag[8..].copy_from_slice(&sequence.rotate_left(17).to_le_bytes());
    payload.extend_from_slice(&recipient_tag);

    let mut envelope_nonce = [0u8; 24];
    envelope_nonce[..8].copy_from_slice(&sequence.to_le_bytes());
    envelope_nonce[8..16].copy_from_slice(&sequence.wrapping_mul(0x9e37_79b9_7f4a_7c15).to_le_bytes());
    envelope_nonce[16..].copy_from_slice(&sequence.rotate_right(11).to_le_bytes());
    payload.extend_from_slice(&envelope_nonce);

    payload.push(1);
    payload.push(32);
    payload.extend_from_slice(&sender_pubkey);
    payload.extend((0..body_len).map(|offset| sequence.wrapping_add(offset as u64) as u8));
    assert!(payload.len() <= 2_048);
    payload
}

fn build_payload_tx(signer: Keypair, utxo: &(TransactionOutpoint, UtxoEntry), pay_address: &Address, payload: Vec<u8>) -> Transaction {
    let minimum_fee = required_fee(1, 1);
    let output_value = (utxo.1.amount / 2).max(1);
    assert!(utxo.1.amount.saturating_sub(output_value) >= minimum_fee);
    let input = TransactionInput { previous_outpoint: utxo.0, signature_script: vec![], sequence: 0, sig_op_count: 1 };
    let output = TransactionOutput { value: output_value, script_public_key: pay_to_address_script(pay_address) };
    let unsigned = Transaction::new(TX_VERSION, vec![input], vec![output], 0, SUBNETWORK_ID_PAYLOAD, 0, payload);
    sign(MutableTransaction::with_entries(unsigned, vec![utxo.1.clone()]), signer).tx
}

fn build_native_tx(signer: Keypair, utxo: &(TransactionOutpoint, UtxoEntry), pay_address: &Address) -> Transaction {
    let minimum_fee = required_fee(1, 1);
    let output_value = (utxo.1.amount / 2).max(1);
    assert!(utxo.1.amount.saturating_sub(output_value) >= minimum_fee);
    let input = TransactionInput { previous_outpoint: utxo.0, signature_script: vec![], sequence: 0, sig_op_count: 1 };
    let output = TransactionOutput { value: output_value, script_public_key: pay_to_address_script(pay_address) };
    let unsigned = Transaction::new(TX_VERSION, vec![input], vec![output], 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    sign(MutableTransaction::with_entries(unsigned, vec![utxo.1.clone()]), signer).tx
}

fn build_stress_payload_tx(
    signer: Keypair,
    utxo: &(TransactionOutpoint, UtxoEntry),
    pay_address: &Address,
    payload: Vec<u8>,
) -> Transaction {
    let minimum_fee = required_fee(1, 1);
    assert!(utxo.1.amount > minimum_fee, "stress payload UTXO is too small for fee-preserving change");
    let input = TransactionInput { previous_outpoint: utxo.0, signature_script: vec![], sequence: 0, sig_op_count: 1 };
    let output = TransactionOutput { value: utxo.1.amount - minimum_fee, script_public_key: pay_to_address_script(pay_address) };
    let unsigned = Transaction::new(TX_VERSION, vec![input], vec![output], 0, SUBNETWORK_ID_PAYLOAD, 0, payload);
    sign(MutableTransaction::with_entries(unsigned, vec![utxo.1.clone()]), signer).tx
}

fn build_stress_native_tx(signer: Keypair, utxo: &(TransactionOutpoint, UtxoEntry), pay_address: &Address) -> Transaction {
    let minimum_fee = required_fee(1, 1);
    assert!(utxo.1.amount > minimum_fee, "stress native UTXO is too small for fee-preserving change");
    let input = TransactionInput { previous_outpoint: utxo.0, signature_script: vec![], sequence: 0, sig_op_count: 1 };
    let output = TransactionOutput { value: utxo.1.amount - minimum_fee, script_public_key: pay_to_address_script(pay_address) };
    let unsigned = Transaction::new(TX_VERSION, vec![input], vec![output], 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    sign(MutableTransaction::with_entries(unsigned, vec![utxo.1.clone()]), signer).tx
}

fn build_stress_wallet_funding_tx(
    signer: Keypair,
    utxo: &(TransactionOutpoint, UtxoEntry),
    fund_address: &Address,
    change_address: &Address,
    funding_outputs: usize,
) -> Transaction {
    let output_count = funding_outputs + 1;
    let minimum_fee = required_fee(1, output_count as u64);
    assert!(utxo.1.amount > minimum_fee, "stress wallet funding UTXO is too small");
    let spendable = utxo.1.amount - minimum_fee;
    let funding_value = spendable / (funding_outputs as u64 + 1);
    assert!(funding_value > required_fee(1, 1), "stress wallet funding output is too small: funding_value={funding_value}");

    let mut outputs = Vec::with_capacity(output_count);
    for _ in 0..funding_outputs {
        outputs.push(TransactionOutput { value: funding_value, script_public_key: pay_to_address_script(fund_address) });
    }
    outputs.push(TransactionOutput {
        value: spendable - funding_value * funding_outputs as u64,
        script_public_key: pay_to_address_script(change_address),
    });

    let input = TransactionInput { previous_outpoint: utxo.0, signature_script: vec![], sequence: 0, sig_op_count: 1 };
    let unsigned = Transaction::new(TX_VERSION, vec![input], outputs, 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    sign(MutableTransaction::with_entries(unsigned, vec![utxo.1.clone()]), signer).tx
}

fn build_payload_tx_with_outputs(
    signer_secret: &secp256k1::SecretKey,
    inputs: Vec<(TransactionOutpoint, UtxoEntry, u8)>,
    outputs: Vec<TransactionOutput>,
    payload: Vec<u8>,
) -> Transaction {
    let tx_inputs = inputs
        .iter()
        .map(|(previous_outpoint, _, sig_op_count)| TransactionInput {
            previous_outpoint: *previous_outpoint,
            signature_script: vec![],
            sequence: 0,
            sig_op_count: *sig_op_count,
        })
        .collect();
    let entries = inputs.into_iter().map(|(_, entry, _)| entry).collect();
    let unsigned = Transaction::new(TX_VERSION, tx_inputs, outputs, 0, SUBNETWORK_ID_PAYLOAD, 0, payload);
    sign_with_multiple_v2(MutableTransaction::with_entries(unsigned, entries), &[signer_secret.secret_bytes()]).unwrap().tx
}

fn is_temporarily_atomic_unready(err: &impl ToString) -> bool {
    let message = err.to_string();
    message.contains("ERR_STALE_CONTEXT")
        || message.contains("Atomic token index is not ready")
        || message.contains("node is not nearly synced after payload hardfork")
}

async fn wait_for_atomic_mining_ready(client: &GrpcClient) {
    for _ in 0..200 {
        if client
            .get_server_info()
            .await
            .map(|info| info.virtual_daa_score.saturating_add(1) < ATOMIC_TEST_PAYLOAD_HF_DAA)
            .unwrap_or(false)
        {
            return;
        }

        match client.get_token_health_call(None, GetTokenHealthRequest { at_block_hash: None }).await {
            Ok(health)
                if health.token_state == "healthy"
                    && !health.is_degraded
                    && !health.bootstrap_in_progress
                    && health.live_correct
                    && health.last_applied_block.is_some() =>
            {
                return;
            }
            Ok(_) => {}
            Err(err) if is_temporarily_atomic_unready(&err) => {}
            Err(err) => panic!("unexpected Atomic health error while waiting for mining readiness: {err}"),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("Atomic token index did not become mining-ready in time");
}

async fn mine_blocks(client: &GrpcClient, pay_address: &Address, count: u64) {
    for _ in 0..count {
        wait_for_atomic_mining_ready(client).await;
        let before = client.get_server_info().await.unwrap().virtual_daa_score;
        let template = loop {
            match client.get_block_template(pay_address.clone(), vec![]).await {
                Ok(template) => break template,
                Err(err) if is_temporarily_atomic_unready(&err) => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
                Err(err) => panic!("get_block_template failed while mining test block: {err}"),
            }
        };
        client.submit_block(template.block, false).await.unwrap();
        let check_client = client.clone();
        wait_for(
            20,
            200,
            move || {
                async fn advanced(client: GrpcClient, before: u64) -> bool {
                    client.get_server_info().await.map(|s| s.virtual_daa_score > before).unwrap_or(false)
                }
                Box::pin(advanced(check_client.clone(), before))
            },
            "virtual DAA score did not advance after mined block",
        )
        .await;
    }
}

async fn mine_block_and_count_transactions(client: &GrpcClient, pay_address: &Address) -> usize {
    wait_for_atomic_mining_ready(client).await;
    let before = client.get_server_info().await.unwrap().virtual_daa_score;
    let template = loop {
        match client.get_block_template(pay_address.clone(), vec![]).await {
            Ok(template) => break template,
            Err(err) if is_temporarily_atomic_unready(&err) => {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            Err(err) => panic!("get_block_template failed while mining stress block: {err}"),
        }
    };
    let tx_count = template.block.transactions.len();
    client.submit_block(template.block, false).await.unwrap();
    let check_client = client.clone();
    wait_for(
        20,
        200,
        move || {
            async fn advanced(client: GrpcClient, before: u64) -> bool {
                client.get_server_info().await.map(|s| s.virtual_daa_score > before).unwrap_or(false)
            }
            Box::pin(advanced(check_client.clone(), before))
        },
        "virtual DAA score did not advance after mined stress block",
    )
    .await;
    tx_count
}

async fn mine_until_spendable_utxos(
    client: &GrpcClient,
    address: &Address,
    coinbase_maturity: u64,
    min_utxos: usize,
) -> Vec<(TransactionOutpoint, UtxoEntry)> {
    for _ in 0..ATOMIC_LONG_STRESS_INDEX_WAIT_ATTEMPTS {
        let utxos = fetch_spendable_utxos(client, address.clone(), coinbase_maturity).await;
        if utxos.len() >= min_utxos {
            return utxos;
        }
        mine_blocks(client, address, 1).await;
    }
    panic!("failed to mine enough spendable UTXOs for Atomic token flow");
}

async fn submit_and_wait_indexed(client: &GrpcClient, tx: &Transaction, pay_address: &Address) {
    client.submit_transaction(tx.into(), false).await.unwrap();
    client.get_mempool_entry(tx.id(), false, false).await.unwrap();
    for _ in 0..200 {
        mine_blocks(client, pay_address, 1).await;
        let health = client.get_token_health_call(None, GetTokenHealthRequest { at_block_hash: None }).await.unwrap();
        assert!(!health.is_degraded, "atomic service degraded before indexing tx status");
        let status =
            client.get_token_op_status_call(None, GetTokenOpStatusRequest { txid: tx.id(), at_block_hash: None }).await.unwrap();
        if status.apply_status.is_some() {
            return;
        }
    }
    panic!("token status was not indexed in time for tx {}", tx.id());
}

async fn submit_transaction_and_assert_mempool(client: &GrpcClient, label: &str, tx: &Transaction) {
    let txid = tx.id();
    client.submit_transaction(tx.into(), false).await.unwrap_or_else(|err| panic!("submit {label} failed: {err}"));
    client.get_mempool_entry(txid, false, false).await.unwrap_or_else(|err| panic!("missing mempool entry for {label}: {err}"));
}

async fn submit_transactions_parallel_owned(client: GrpcClient, txs: Vec<(String, Transaction)>, parallelism: usize) {
    for chunk in txs.chunks(parallelism.max(1)) {
        let mut handles = Vec::with_capacity(chunk.len());
        for (label, tx) in chunk.iter().cloned() {
            let client = client.clone();
            handles.push(tokio::spawn(async move {
                submit_transaction_and_assert_mempool(&client, &label, &tx).await;
            }));
        }
        for handle in handles {
            handle.await.expect("parallel submit task panicked");
        }
    }
}

fn stress_duration_from_env() -> Duration {
    let seconds = std::env::var("CRYPTIX_STRESS_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(ATOMIC_LONG_STRESS_DEFAULT_SECONDS);
    Duration::from_secs(seconds.max(1))
}

fn stress_index_wait_attempts_from_env() -> usize {
    std::env::var("CRYPTIX_STRESS_INDEX_WAIT_ATTEMPTS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(ATOMIC_LONG_STRESS_INDEX_WAIT_ATTEMPTS)
        .max(1)
}

fn reorg_stress_rounds_from_env() -> u64 {
    std::env::var("CRYPTIX_REORG_STRESS_ROUNDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(ATOMIC_REORG_STRESS_DEFAULT_ROUNDS)
        .max(1)
}

#[derive(Clone)]
struct StressInputTrace {
    outpoint: TransactionOutpoint,
    amount: u64,
    block_daa_score: u64,
    is_coinbase: bool,
    producer_accepted_or_mature_coinbase: bool,
}

#[derive(Clone)]
struct StressTxTrace {
    label: String,
    txid: TransactionId,
    inputs: Vec<StressInputTrace>,
}

struct StressWallet {
    label: String,
    secret: secp256k1::SecretKey,
    address: Address,
    owner_id: [u8; 32],
    owner_id_hex: String,
    pubkey_bytes: [u8; 32],
    queue: VecDeque<(TransactionOutpoint, UtxoEntry)>,
    consumed_outpoints: HashSet<TransactionOutpoint>,
    owner_nonce: u64,
    expected_base_balance: u128,
}

impl StressWallet {
    fn keypair(&self) -> Keypair {
        Keypair::from_secret_key(secp256k1::SECP256K1, &self.secret)
    }
}

fn stress_tx_trace(
    label: String,
    txid: TransactionId,
    inputs: Vec<(TransactionOutpoint, UtxoEntry)>,
    accepted_producer_txids: &HashSet<TransactionId>,
) -> StressTxTrace {
    let inputs = inputs
        .into_iter()
        .map(|(outpoint, entry)| StressInputTrace {
            outpoint,
            amount: entry.amount,
            block_daa_score: entry.block_daa_score,
            is_coinbase: entry.is_coinbase,
            producer_accepted_or_mature_coinbase: entry.is_coinbase || accepted_producer_txids.contains(&outpoint.transaction_id),
        })
        .collect();
    StressTxTrace { label, txid, inputs }
}

fn consensus_manager_from_daemon(daemon: &Daemon) -> std::sync::Arc<ConsensusManager> {
    std::sync::Arc::downcast::<ConsensusManager>(daemon.core.find(ConsensusManager::IDENT).unwrap().arc_any()).unwrap()
}

async fn virtual_utxo_entry_exact(consensus_manager: &ConsensusManager, outpoint: TransactionOutpoint) -> Option<UtxoEntry> {
    let mut entries = consensus_manager.consensus().unguarded_session().async_get_virtual_utxos(Some(outpoint), 1, false).await;
    match entries.pop() {
        Some((found_outpoint, entry)) if found_outpoint == outpoint => Some(entry),
        _ => None,
    }
}

fn pop_stress_utxo(
    queue: &mut VecDeque<(TransactionOutpoint, UtxoEntry)>,
    consumed: &mut HashSet<TransactionOutpoint>,
    label: &str,
) -> (TransactionOutpoint, UtxoEntry) {
    while let Some(utxo) = queue.pop_front() {
        if consumed.insert(utxo.0) {
            return utxo;
        }
    }
    panic!("stress UTXO queue exhausted while building {label}");
}

fn pop_stress_utxo_with_min_amount(
    queue: &mut VecDeque<(TransactionOutpoint, UtxoEntry)>,
    consumed: &mut HashSet<TransactionOutpoint>,
    label: &str,
    min_amount_exclusive: u64,
) -> (TransactionOutpoint, UtxoEntry) {
    let original_len = queue.len();
    for _ in 0..original_len {
        let Some(utxo) = queue.pop_front() else {
            break;
        };
        if consumed.contains(&utxo.0) {
            continue;
        }
        if utxo.1.amount > min_amount_exclusive {
            consumed.insert(utxo.0);
            return utxo;
        }
        queue.push_back(utxo);
    }
    panic!("stress UTXO queue exhausted while building {label}; no available UTXO above {min_amount_exclusive} sompi");
}

async fn refill_stress_utxos(
    client: &GrpcClient,
    consensus_manager: &ConsensusManager,
    address: &Address,
    coinbase_maturity: u64,
    queue: &mut VecDeque<(TransactionOutpoint, UtxoEntry)>,
    consumed: &HashSet<TransactionOutpoint>,
    accepted_producer_txids: &HashSet<TransactionId>,
    min_available: usize,
) {
    for _ in 0..80 {
        let mut queued: HashSet<_> = queue.iter().map(|(outpoint, _)| *outpoint).collect();
        for utxo in fetch_spendable_utxos(client, address.clone(), coinbase_maturity).await {
            let producer_is_accepted = utxo.1.is_coinbase || accepted_producer_txids.contains(&utxo.0.transaction_id);
            if !producer_is_accepted || consumed.contains(&utxo.0) || !queued.insert(utxo.0) {
                continue;
            }
            let Some(virtual_entry) = virtual_utxo_entry_exact(consensus_manager, utxo.0).await else {
                continue;
            };
            if virtual_entry.amount == utxo.1.amount
                && virtual_entry.block_daa_score == utxo.1.block_daa_score
                && virtual_entry.is_coinbase == utxo.1.is_coinbase
            {
                queue.push_back((utxo.0, virtual_entry));
            }
        }
        if queue.len() >= min_available {
            return;
        }
        mine_blocks(client, address, 1).await;
    }
    panic!("failed to refill stress UTXO queue to {min_available}; available={}", queue.len());
}

async fn drain_stress_mempool(client: &GrpcClient, pay_address: &Address, label: &str) -> (usize, u64) {
    let mut max_block_txs = 0usize;
    let mut mined_blocks = 0u64;
    for _ in 0..120 {
        let remaining = client.get_mempool_entries(false, false).await.unwrap();
        if remaining.is_empty() {
            if mined_blocks > 0 {
                let tx_count = mine_block_and_count_transactions(client, pay_address).await;
                max_block_txs = max_block_txs.max(tx_count);
                mined_blocks += 1;
            }
            return (max_block_txs, mined_blocks);
        }
        let tx_count = mine_block_and_count_transactions(client, pay_address).await;
        max_block_txs = max_block_txs.max(tx_count);
        mined_blocks += 1;
    }
    let remaining = client.get_mempool_entries(false, false).await.unwrap();
    assert!(remaining.is_empty(), "{label} mempool did not drain after stress mining: remaining={}", remaining.len());
    (max_block_txs, mined_blocks)
}

async fn assert_token_statuses_applied(
    client: &GrpcClient,
    txids: &[(String, cryptix_consensus_core::tx::TransactionId)],
    label: &str,
) {
    let mut pending = txids.to_vec();
    for _ in 0..stress_index_wait_attempts_from_env() {
        let mut next_pending = Vec::new();
        for (tx_label, txid) in pending {
            match client.get_token_op_status_call(None, GetTokenOpStatusRequest { txid, at_block_hash: None }).await {
                Ok(status) if status.apply_status == Some(0) => {}
                Ok(status) if status.apply_status.is_some() => panic!(
                    "unexpected Atomic apply status for {label}/{tx_label} tx {txid}: apply_status={:?} noop_reason={:?}",
                    status.apply_status, status.noop_reason
                ),
                Ok(_) | Err(_) => next_pending.push((tx_label, txid)),
            }
        }
        if next_pending.is_empty() {
            return;
        }
        pending = next_pending;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let sample = pending.iter().take(8).map(|(tx_label, txid)| format!("{tx_label}:{txid}")).collect::<Vec<_>>().join(", ");
    panic!("Atomic statuses did not apply in time for {label}; pending={} sample=[{sample}]", pending.len());
}

async fn assert_txids_accepted_since(
    client: &GrpcClient,
    from_hash: cryptix_hashes::Hash,
    txs: &[StressTxTrace],
    label: &str,
) -> HashSet<TransactionId> {
    let chain = client.get_virtual_chain_from_block(from_hash, true).await.unwrap();
    let accepted: HashSet<_> =
        chain.accepted_transaction_ids.iter().flat_map(|entry| entry.accepted_transaction_ids.iter().copied()).collect();
    let missing = txs
        .iter()
        .filter(|tx| !accepted.contains(&tx.txid))
        .take(12)
        .map(|tx| {
            let inputs = tx
                .inputs
                .iter()
                .map(|input| {
                    format!(
                        "{} amount={} daa={} coinbase={} accepted_or_mature_coinbase={}",
                        input.outpoint,
                        input.amount,
                        input.block_daa_score,
                        input.is_coinbase,
                        input.producer_accepted_or_mature_coinbase
                    )
                })
                .collect::<Vec<_>>()
                .join("; ");
            format!("{}:{} inputs=[{}]", tx.label, tx.txid, inputs)
        })
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "{label} Atomic txs were not accepted into the selected chain since {from_hash}; added_blocks={} accepted_ids={} missing_sample=[{}]",
        chain.added_chain_block_hashes.len(),
        accepted.len(),
        missing.join(", ")
    );
    accepted
}

async fn wait_for_healthy_atomic_at_sink(
    client: &GrpcClient,
    expected_sink: cryptix_hashes::Hash,
    label: &str,
) -> GetTokenHealthResponse {
    let mut last_health = None;
    let mut last_err = None;
    for _ in 0..stress_index_wait_attempts_from_env() {
        match client.get_token_health_call(None, GetTokenHealthRequest { at_block_hash: None }).await {
            Ok(health)
                if health.token_state == "healthy"
                    && !health.is_degraded
                    && !health.bootstrap_in_progress
                    && health.live_correct
                    && health.last_applied_block == Some(expected_sink) =>
            {
                return health;
            }
            Ok(health) => last_health = Some(health),
            Err(err) if is_temporarily_atomic_unready(&err) => last_err = Some(err.to_string()),
            Err(err) => panic!("unexpected Atomic health error while waiting for {label}: {err}"),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    panic!(
        "Atomic token index did not become healthy at {label} sink {expected_sink}; last_health={last_health:?}; last_err={last_err:?}"
    );
}

async fn assert_consensus_atomic_hash_exists(client: &GrpcClient, block_hash: cryptix_hashes::Hash, label: &str) -> String {
    let response = client
        .get_consensus_atomic_state_hash_call(None, GetConsensusAtomicStateHashRequest { block_hash })
        .await
        .unwrap_or_else(|err| panic!("failed reading consensus Atomic state hash for {label} block {block_hash}: {err}"));
    let state_hash =
        response.state_hash.unwrap_or_else(|| panic!("missing consensus Atomic state hash for {label} block {block_hash}"));
    assert!(!state_hash.is_empty(), "empty consensus Atomic state hash for {label} block {block_hash}");
    state_hash
}

async fn spendable_cpay_snapshot(client: &GrpcClient, address: &Address, coinbase_maturity: u64) -> Vec<(String, u64)> {
    let mut snapshot = fetch_spendable_utxos(client, address.clone(), coinbase_maturity)
        .await
        .into_iter()
        .map(|(outpoint, entry)| (outpoint.to_string(), entry.amount))
        .collect::<Vec<_>>();
    snapshot.sort();
    snapshot
}

async fn import_selected_chain_blocks(
    source: &GrpcClient,
    target: &GrpcClient,
    from_hash: cryptix_hashes::Hash,
    label: &str,
) -> (Vec<cryptix_hashes::Hash>, HashSet<TransactionId>) {
    let chain = source.get_virtual_chain_from_block(from_hash, true).await.unwrap();
    assert!(
        chain.removed_chain_block_hashes.is_empty(),
        "{label} source chain from {from_hash} unexpectedly removed {} blocks",
        chain.removed_chain_block_hashes.len()
    );
    let accepted = chain.accepted_transaction_ids.iter().flat_map(|entry| entry.accepted_transaction_ids.iter().copied()).collect();
    let added_blocks = chain.added_chain_block_hashes;
    assert!(!added_blocks.is_empty(), "{label} selected chain import had no added blocks from {from_hash}");

    for hash in &added_blocks {
        let block = source.get_block_call(None, GetBlockRequest { hash: *hash, include_transactions: true }).await.unwrap().block;
        let raw_block = RpcRawBlock { header: Header::from(&block.header).into(), transactions: block.transactions };
        target.submit_block(raw_block, false).await.unwrap_or_else(|err| panic!("failed importing {label} block {hash}: {err}"));
    }

    (added_blocks, accepted)
}

async fn wait_for_sink(client: &GrpcClient, expected_sink: cryptix_hashes::Hash, label: &'static str) {
    let sink_client = client.clone();
    wait_for(
        100,
        400,
        move || {
            async fn adopted(client: GrpcClient, expected_sink: cryptix_hashes::Hash) -> bool {
                client.get_block_dag_info().await.map(|info| info.sink == expected_sink).unwrap_or(false)
            }
            Box::pin(adopted(sink_client.clone(), expected_sink))
        },
        label,
    )
    .await;
}

struct LiquidityBranchResult {
    txids: Vec<(String, TransactionId)>,
    claim_txid: TransactionId,
    claim_amount_sompi: u64,
}

async fn apply_liquidity_buy_sell_claim_branch(
    client: &GrpcClient,
    owner_secret: &secp256k1::SecretKey,
    owner_address: &Address,
    asset_id: &str,
    asset_id_bytes: [u8; 32],
    start_pool: &RpcLiquidityPoolState,
    buy_utxo: &(TransactionOutpoint, UtxoEntry),
    buy_in_sompi: u64,
    sell_token_in: u128,
    claim_amount_sompi: u64,
    label: &str,
) -> LiquidityBranchResult {
    let buy_quote = client
        .get_liquidity_quote_call(
            None,
            GetLiquidityQuoteRequest {
                asset_id: asset_id.to_string(),
                side: 0,
                exact_in_amount: buy_in_sompi.to_string(),
                at_block_hash: None,
            },
        )
        .await
        .unwrap();
    let canonical_buy_in_sompi = buy_quote.exact_in_amount.parse::<u64>().unwrap();
    let buy_min_token_out = buy_quote.amount_out.parse::<u128>().unwrap();
    let buy_fee = required_fee(2, 2);
    assert!(
        buy_utxo.1.amount > canonical_buy_in_sompi + buy_fee,
        "{label} buy UTXO is too small: amount={} requested_buy_in={} canonical_buy_in={} fee={}",
        buy_utxo.1.amount,
        buy_in_sompi,
        canonical_buy_in_sompi,
        buy_fee
    );
    let buy_change = buy_utxo.1.amount - canonical_buy_in_sompi - buy_fee;
    let start_vault_value = start_pool.vault_value_sompi.parse::<u64>().unwrap();
    let buy_tx = build_payload_tx_with_outputs(
        owner_secret,
        vec![
            (
                TransactionOutpoint::new(start_pool.vault_txid, start_pool.vault_output_index),
                UtxoEntry::new(start_vault_value, liquidity_vault_script(), 0, false),
                0,
            ),
            (buy_utxo.0, buy_utxo.1.clone(), 1),
        ],
        vec![
            TransactionOutput { value: start_vault_value + canonical_buy_in_sompi, script_public_key: liquidity_vault_script() },
            TransactionOutput { value: buy_change, script_public_key: pay_to_address_script(owner_address) },
        ],
        payload_buy_liquidity(1, 1, asset_id_bytes, start_pool.pool_nonce, canonical_buy_in_sompi, buy_min_token_out),
    );
    let buy_txid = buy_tx.id();
    submit_and_wait_indexed(client, &buy_tx, owner_address).await;

    let pool_after_buy = client
        .get_liquidity_pool_state_call(None, GetLiquidityPoolStateRequest { asset_id: asset_id.to_string(), at_block_hash: None })
        .await
        .unwrap()
        .pool
        .unwrap_or_else(|| panic!("{label} pool missing after buy"));
    assert_eq!(pool_after_buy.pool_nonce, start_pool.pool_nonce + 1, "{label} buy must advance pool nonce");
    let unclaimed_after_buy = pool_after_buy.unclaimed_fee_total_sompi.parse::<u64>().unwrap();
    assert!(unclaimed_after_buy > 0, "{label} buy must accrue claimable CPAY fees");

    let sell_quote = client
        .get_liquidity_quote_call(
            None,
            GetLiquidityQuoteRequest {
                asset_id: asset_id.to_string(),
                side: 1,
                exact_in_amount: sell_token_in.to_string(),
                at_block_hash: None,
            },
        )
        .await
        .unwrap();
    let sell_cpay_out = sell_quote.amount_out.parse::<u64>().unwrap();
    let sell_fee = required_fee(2, 3);
    let sell_change = buy_change.checked_sub(sell_fee).unwrap_or_else(|| panic!("{label} sell change underflow"));
    let pool_after_buy_vault = pool_after_buy.vault_value_sompi.parse::<u64>().unwrap();
    let sell_vault_value =
        pool_after_buy_vault.checked_sub(sell_cpay_out).unwrap_or_else(|| panic!("{label} sell cpay out exceeds pool vault"));
    let sell_tx = build_payload_tx_with_outputs(
        owner_secret,
        vec![
            (
                TransactionOutpoint::new(pool_after_buy.vault_txid, pool_after_buy.vault_output_index),
                UtxoEntry::new(pool_after_buy_vault, liquidity_vault_script(), 0, false),
                0,
            ),
            (TransactionOutpoint::new(buy_txid, 1), UtxoEntry::new(buy_change, pay_to_address_script(owner_address), 0, false), 1),
        ],
        vec![
            TransactionOutput { value: sell_vault_value, script_public_key: liquidity_vault_script() },
            TransactionOutput { value: sell_cpay_out, script_public_key: pay_to_address_script(owner_address) },
            TransactionOutput { value: sell_change, script_public_key: pay_to_address_script(owner_address) },
        ],
        payload_sell_liquidity(1, 2, asset_id_bytes, pool_after_buy.pool_nonce, sell_token_in, sell_cpay_out, 1),
    );
    let sell_txid = sell_tx.id();
    submit_and_wait_indexed(client, &sell_tx, owner_address).await;

    let pool_after_sell = client
        .get_liquidity_pool_state_call(None, GetLiquidityPoolStateRequest { asset_id: asset_id.to_string(), at_block_hash: None })
        .await
        .unwrap()
        .pool
        .unwrap_or_else(|| panic!("{label} pool missing after sell"));
    assert_eq!(pool_after_sell.pool_nonce, start_pool.pool_nonce + 2, "{label} sell must advance pool nonce");
    let unclaimed_after_sell = pool_after_sell.unclaimed_fee_total_sompi.parse::<u64>().unwrap();
    assert!(
        unclaimed_after_sell >= claim_amount_sompi,
        "{label} does not have enough claimable fees: unclaimed={} claim={}",
        unclaimed_after_sell,
        claim_amount_sompi
    );

    let claim_fee = required_fee(2, 3);
    let claim_change = sell_change.checked_sub(claim_fee).unwrap_or_else(|| panic!("{label} claim change underflow"));
    let pool_after_sell_vault = pool_after_sell.vault_value_sompi.parse::<u64>().unwrap();
    let claim_vault_value =
        pool_after_sell_vault.checked_sub(claim_amount_sompi).unwrap_or_else(|| panic!("{label} claim amount exceeds pool vault"));
    let claim_tx = build_payload_tx_with_outputs(
        owner_secret,
        vec![
            (
                TransactionOutpoint::new(pool_after_sell.vault_txid, pool_after_sell.vault_output_index),
                UtxoEntry::new(pool_after_sell_vault, liquidity_vault_script(), 0, false),
                0,
            ),
            (TransactionOutpoint::new(sell_txid, 2), UtxoEntry::new(sell_change, pay_to_address_script(owner_address), 0, false), 1),
        ],
        vec![
            TransactionOutput { value: claim_vault_value, script_public_key: liquidity_vault_script() },
            TransactionOutput { value: claim_amount_sompi, script_public_key: pay_to_address_script(owner_address) },
            TransactionOutput { value: claim_change, script_public_key: pay_to_address_script(owner_address) },
        ],
        payload_claim_liquidity(1, 3, asset_id_bytes, pool_after_sell.pool_nonce, 0, claim_amount_sompi, 1),
    );
    let claim_txid = claim_tx.id();
    submit_and_wait_indexed(client, &claim_tx, owner_address).await;

    let txids = vec![(format!("{label}-buy"), buy_txid), (format!("{label}-sell"), sell_txid), (format!("{label}-claim"), claim_txid)];
    assert_token_statuses_applied(client, &txids, label).await;
    let pool_after_claim = client
        .get_liquidity_pool_state_call(None, GetLiquidityPoolStateRequest { asset_id: asset_id.to_string(), at_block_hash: None })
        .await
        .unwrap()
        .pool
        .unwrap_or_else(|| panic!("{label} pool missing after claim"));
    assert_eq!(pool_after_claim.pool_nonce, start_pool.pool_nonce + 3, "{label} claim must advance pool nonce");

    LiquidityBranchResult { txids, claim_txid, claim_amount_sompi }
}

fn atomic_args() -> Args {
    Args {
        simnet: true,
        disable_upnp: true,
        enable_unsynced_mining: true,
        block_template_cache_lifetime: Some(0),
        utxoindex: true,
        unsafe_rpc: true,
        atomic_unsafe_skip_snapshot_finality_check: true,
        payload_hf_activation_daa_score: Some(ATOMIC_TEST_PAYLOAD_HF_DAA),
        coinbase_maturity_override: Some(10),
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn atomic_token_atomic_enabled_not_ready_state_fails_closed() {
    cryptix_core::log::try_init_logger("INFO");
    let mut daemon = Daemon::new_random_with_args(atomic_args(), 10);
    let client = daemon.start().await;

    let health = match client.get_token_health_call(None, GetTokenHealthRequest { at_block_hash: None }).await {
        Ok(health) => health,
        Err(err) if is_temporarily_atomic_unready(&err) => return,
        Err(err) => panic!("unexpected token health error: {err}"),
    };
    assert!(!health.is_degraded);
    if health.token_state == "healthy" {
        return;
    }
    assert!(
        matches!(health.token_state.as_str(), "not_ready" | "recovering"),
        "expected explicit not-ready/recovering state, got {}",
        health.token_state
    );

    let zero_hex = hex32([0u8; 32]);
    let balance_err = client
        .get_token_balance_call(
            None,
            GetTokenBalanceRequest { asset_id: zero_hex.clone(), owner_id: zero_hex.clone(), at_block_hash: None },
        )
        .await
        .unwrap_err();
    assert!(
        balance_err.to_string().contains("Cryptix Atomic state unavailable"),
        "expected fail-closed not-ready error, got: {balance_err}"
    );

    let nonce_err = client
        .get_token_nonce_call(None, GetTokenNonceRequest { owner_id: zero_hex.clone(), asset_id: None, at_block_hash: None })
        .await
        .unwrap_err();
    assert!(
        nonce_err.to_string().contains("Cryptix Atomic state unavailable"),
        "expected fail-closed not-ready error, got: {nonce_err}"
    );

    let spendability_err = client
        .get_token_spendability_call(
            None,
            GetTokenSpendabilityRequest {
                asset_id: zero_hex.clone(),
                owner_id: zero_hex,
                min_daa_for_spend: Some(10),
                at_block_hash: None,
            },
        )
        .await
        .unwrap_err();
    assert!(
        spendability_err.to_string().contains("Cryptix Atomic state unavailable"),
        "expected fail-closed not-ready error, got: {spendability_err}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn atomic_token_atomic_enabled_e2e_transfer_mint_burn_snapshot() {
    cryptix_core::log::try_init_logger("INFO");
    let mut daemon = Daemon::new_random_with_args(atomic_args(), 10);
    let client = daemon.start().await;

    let (owner_sk, owner_pk) = secp256k1::generate_keypair(&mut thread_rng());
    let owner_address = Address::new(daemon.network.into(), Version::PubKey, &owner_pk.x_only_public_key().0.serialize());

    let (_recv_sk, recv_pk) = secp256k1::generate_keypair(&mut thread_rng());
    let receiver_address = Address::new(daemon.network.into(), Version::PubKey, &recv_pk.x_only_public_key().0.serialize());
    let owner_id = owner_id_from_address(&owner_address);
    let receiver_id = owner_id_from_address(&receiver_address);
    let owner_id_hex = hex32(owner_id);
    let receiver_id_hex = hex32(receiver_id);
    let coinbase_maturity = daemon.args.read().coinbase_maturity_override.unwrap_or(SIMNET_PARAMS.coinbase_maturity);

    let mut utxos = mine_until_spendable_utxos(&client, &owner_address, coinbase_maturity, 4).await;
    utxos.truncate(4);

    let create_tx = build_payload_tx(
        Keypair::from_secret_key(secp256k1::SECP256K1, &owner_sk),
        &utxos[0],
        &owner_address,
        payload_create_asset(0, 1, 8, owner_id, b"AtomicToken", b"ATM", b"\x01"),
    );
    submit_and_wait_indexed(&client, &create_tx, &owner_address).await;
    let asset_id = create_tx.id().to_string();
    let asset_id_bytes = create_tx.id().as_bytes();

    let mint_tx = build_payload_tx(
        Keypair::from_secret_key(secp256k1::SECP256K1, &owner_sk),
        &utxos[1],
        &owner_address,
        payload_mint(0, 1, asset_id_bytes, owner_id, 1000),
    );
    submit_and_wait_indexed(&client, &mint_tx, &owner_address).await;

    let transfer_tx = build_payload_tx(
        Keypair::from_secret_key(secp256k1::SECP256K1, &owner_sk),
        &utxos[2],
        &owner_address,
        payload_transfer(0, 2, asset_id_bytes, receiver_id, 300),
    );
    submit_and_wait_indexed(&client, &transfer_tx, &owner_address).await;

    let burn_tx = build_payload_tx(
        Keypair::from_secret_key(secp256k1::SECP256K1, &owner_sk),
        &utxos[3],
        &owner_address,
        payload_burn(0, 3, asset_id_bytes, 200),
    );
    submit_and_wait_indexed(&client, &burn_tx, &owner_address).await;

    for txid in [create_tx.id(), mint_tx.id(), transfer_tx.id(), burn_tx.id()] {
        let status = client.get_token_op_status_call(None, GetTokenOpStatusRequest { txid, at_block_hash: None }).await.unwrap();
        assert_eq!(
            status.apply_status,
            Some(0),
            "unexpected token status for tx {}: apply_status={:?} noop_reason={:?}",
            txid,
            status.apply_status,
            status.noop_reason
        );
    }

    let owner_balance = client
        .get_token_balance_call(
            None,
            GetTokenBalanceRequest { asset_id: asset_id.clone(), owner_id: owner_id_hex.clone(), at_block_hash: None },
        )
        .await
        .unwrap();
    assert_eq!(owner_balance.balance, "500");

    let receiver_balance = client
        .get_token_balance_call(
            None,
            GetTokenBalanceRequest { asset_id: asset_id.clone(), owner_id: receiver_id_hex.clone(), at_block_hash: None },
        )
        .await
        .unwrap();
    assert_eq!(receiver_balance.balance, "300");

    let asset = client
        .get_token_asset_call(None, GetTokenAssetRequest { asset_id: asset_id.clone(), at_block_hash: None })
        .await
        .unwrap()
        .asset
        .expect("asset must exist");
    assert_eq!(asset.total_supply, "800");

    let nonce = client
        .get_token_nonce_call(None, GetTokenNonceRequest { owner_id: hex32(owner_id), asset_id: None, at_block_hash: None })
        .await
        .unwrap();
    assert_eq!(nonce.expected_next_nonce, 2);
    let token_nonce = client
        .get_token_nonce_call(
            None,
            GetTokenNonceRequest { owner_id: hex32(owner_id), asset_id: Some(asset_id.clone()), at_block_hash: None },
        )
        .await
        .unwrap();
    assert_eq!(token_nonce.expected_next_nonce, 4);

    let events = client
        .get_token_events_call(None, GetTokenEventsRequest { after_sequence: 0, limit: 100, at_block_hash: None })
        .await
        .unwrap();
    assert!(events.events.len() >= 4);
    assert!(events.events.iter().any(|e| e.apply_status == 0));

    let assets = client
        .get_token_assets_call(None, GetTokenAssetsRequest { offset: 0, limit: 100, query: None, at_block_hash: None })
        .await
        .unwrap();
    assert!(assets.total >= 1);
    assert!(assets.assets.iter().any(|a| a.asset_id == asset_id));

    let filtered_assets = client
        .get_token_assets_call(
            None,
            GetTokenAssetsRequest { offset: 0, limit: 100, query: Some("atm".to_string()), at_block_hash: None },
        )
        .await
        .unwrap();
    assert!(filtered_assets.assets.iter().any(|a| a.asset_id == asset_id));

    let owner_balances = client
        .get_token_balances_by_owner_call(
            None,
            GetTokenBalancesByOwnerRequest {
                owner_id: owner_id_hex.clone(),
                offset: 0,
                limit: 100,
                include_assets: true,
                at_block_hash: None,
            },
        )
        .await
        .unwrap();
    assert!(owner_balances.balances.iter().any(|entry| entry.asset_id == asset_id && entry.balance == "500"));
    assert!(owner_balances
        .balances
        .iter()
        .any(|entry| entry.asset_id == asset_id && entry.asset.as_ref().map_or(false, |asset| asset.symbol == "ATM")));

    let holders = client
        .get_token_holders_call(
            None,
            GetTokenHoldersRequest { asset_id: asset_id.clone(), offset: 0, limit: 100, at_block_hash: None },
        )
        .await
        .unwrap();
    assert_eq!(holders.total, 2);
    assert!(holders.holders.iter().any(|entry| entry.owner_id == owner_id_hex && entry.balance == "500"));
    assert!(holders.holders.iter().any(|entry| entry.owner_id == receiver_id_hex && entry.balance == "300"));

    let owner_derived = client
        .get_token_owner_id_by_address_call(
            None,
            GetTokenOwnerIdByAddressRequest { address: owner_address.to_string(), at_block_hash: None },
        )
        .await
        .unwrap();
    assert_eq!(owner_derived.owner_id, Some(hex32(owner_id)));
    assert_eq!(owner_derived.reason, None);

    let snapshot_dir = tempfile::tempdir().unwrap();
    let snapshot_path: PathBuf = snapshot_dir.path().join("atomic.snapshot");
    client
        .export_token_snapshot_call(None, ExportTokenSnapshotRequest { path: snapshot_path.to_string_lossy().to_string() })
        .await
        .unwrap();
    client
        .import_token_snapshot_call(None, ImportTokenSnapshotRequest { path: snapshot_path.to_string_lossy().to_string() })
        .await
        .unwrap();

    let health = client.get_token_health_call(None, GetTokenHealthRequest { at_block_hash: None }).await.unwrap();
    assert!(!health.is_degraded);
    assert!(!health.bootstrap_in_progress);
    assert!(health.live_correct);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn atomic_token_atomic_enabled_mixed_mempool_stress_drains_deterministically() {
    cryptix_core::log::try_init_logger("INFO");
    let mut daemon = Daemon::new_random_with_args(atomic_args(), 10);
    let client = daemon.start().await;

    let (owner_sk, owner_pk) = secp256k1::generate_keypair(&mut thread_rng());
    let owner_address = Address::new(daemon.network.into(), Version::PubKey, &owner_pk.x_only_public_key().0.serialize());
    let (_receiver_sk, receiver_pk) = secp256k1::generate_keypair(&mut thread_rng());
    let receiver_address = Address::new(daemon.network.into(), Version::PubKey, &receiver_pk.x_only_public_key().0.serialize());
    let owner_id = owner_id_from_address(&owner_address);
    let receiver_id = owner_id_from_address(&receiver_address);
    let owner_id_hex = hex32(owner_id);
    let receiver_id_hex = hex32(receiver_id);
    let owner_keypair = || Keypair::from_secret_key(secp256k1::SECP256K1, &owner_sk);
    let coinbase_maturity = daemon.args.read().coinbase_maturity_override.unwrap_or(SIMNET_PARAMS.coinbase_maturity);

    let mut utxos = mine_until_spendable_utxos(&client, &owner_address, coinbase_maturity, 115).await;
    utxos.truncate(115);

    let base_create_tx = build_payload_tx(
        owner_keypair(),
        &utxos[0],
        &owner_address,
        payload_create_asset_with_mint(0, 1, 2, 1_000_000, owner_id, owner_id, 20_000, b"StressBase", b"STB", b"mixed"),
    );
    submit_and_wait_indexed(&client, &base_create_tx, &owner_address).await;
    let base_asset_id = base_create_tx.id().to_string();
    let base_asset_bytes = base_create_tx.id().as_bytes();

    let liquidity_vault_value = MIN_LIQUIDITY_SEED_RESERVE_SOMPI;
    let liquidity_fee = required_fee(1, 2);
    assert!(utxos[1].1.amount > liquidity_vault_value + liquidity_fee);
    let liquidity_change = utxos[1].1.amount - liquidity_vault_value - liquidity_fee;
    let liquidity_fee_bps = 100u16;
    let liquidity_create_tx = build_payload_tx_with_outputs(
        &owner_sk,
        vec![(utxos[1].0, utxos[1].1.clone(), 1)],
        vec![
            TransactionOutput { value: liquidity_vault_value, script_public_key: liquidity_vault_script() },
            TransactionOutput { value: liquidity_change, script_public_key: pay_to_address_script(&owner_address) },
        ],
        payload_create_liquidity_with_fee_recipient(
            0,
            2,
            LIQUIDITY_TOKEN_SUPPLY_RAW,
            liquidity_fee_bps,
            &owner_address,
            0,
            0,
            b"StressPool",
            b"STP",
        ),
    );
    submit_and_wait_indexed(&client, &liquidity_create_tx, &owner_address).await;
    let liquidity_asset_id = liquidity_create_tx.id().to_string();
    let liquidity_asset_bytes = liquidity_create_tx.id().as_bytes();

    let mut parallel_queued = Vec::new();
    let mut ordered_queued = Vec::new();
    let mut token_txids = Vec::new();
    let mut next_utxo = 2usize;
    let mut asset_nonce = 1u64;
    let mut owner_nonce = 3u64;

    for i in 0..20 {
        let native_tx = build_native_tx(owner_keypair(), &utxos[next_utxo], &owner_address);
        next_utxo += 1;
        parallel_queued.push((format!("native-{i}"), native_tx));

        let messenger_tx = build_payload_tx(
            owner_keypair(),
            &utxos[next_utxo],
            &owner_address,
            format!("MSG:atomic-stress:{i}:{}", "x".repeat(256)).into_bytes(),
        );
        next_utxo += 1;
        parallel_queued.push((format!("messenger-{i}"), messenger_tx));

        let create_tx = build_payload_tx(
            owner_keypair(),
            &utxos[next_utxo],
            &owner_address,
            payload_create_asset_with_mint(
                0,
                owner_nonce,
                0,
                1_000_000,
                owner_id,
                owner_id,
                1_000 + i as u128,
                format!("Stress{i:02}").as_bytes(),
                format!("S{i:02}").as_bytes(),
                b"queued",
            ),
        );
        owner_nonce += 1;
        next_utxo += 1;
        token_txids.push((format!("create-{i}"), create_tx.id()));
        ordered_queued.push((format!("create-{i}"), create_tx));

        if i < 12 {
            let mint_tx = build_payload_tx(
                owner_keypair(),
                &utxos[next_utxo],
                &owner_address,
                payload_mint(0, asset_nonce, base_asset_bytes, owner_id, 100),
            );
            next_utxo += 1;
            token_txids.push((format!("mint-{i}"), mint_tx.id()));
            ordered_queued.push((format!("mint-{i}"), mint_tx));
            asset_nonce += 1;

            let transfer_tx = build_payload_tx(
                owner_keypair(),
                &utxos[next_utxo],
                &owner_address,
                payload_transfer(0, asset_nonce, base_asset_bytes, receiver_id, 30),
            );
            next_utxo += 1;
            token_txids.push((format!("transfer-{i}"), transfer_tx.id()));
            ordered_queued.push((format!("transfer-{i}"), transfer_tx));
            asset_nonce += 1;

            let burn_tx = build_payload_tx(
                owner_keypair(),
                &utxos[next_utxo],
                &owner_address,
                payload_burn(0, asset_nonce, base_asset_bytes, 10),
            );
            next_utxo += 1;
            token_txids.push((format!("burn-{i}"), burn_tx.id()));
            ordered_queued.push((format!("burn-{i}"), burn_tx));
            asset_nonce += 1;
        }
    }

    let pool_before = client
        .get_liquidity_pool_state_call(
            None,
            GetLiquidityPoolStateRequest { asset_id: liquidity_asset_id.clone(), at_block_hash: None },
        )
        .await
        .unwrap()
        .pool
        .expect("liquidity pool must exist before queued buy");
    let pool_vault_value = pool_before.vault_value_sompi.parse::<u64>().unwrap();
    let buy_quote = client
        .get_liquidity_quote_call(
            None,
            GetLiquidityQuoteRequest {
                asset_id: liquidity_asset_id.clone(),
                side: 0,
                exact_in_amount: "2000000000".to_string(),
                at_block_hash: None,
            },
        )
        .await
        .unwrap();
    let buy_in_sompi = buy_quote.exact_in_amount.parse::<u64>().unwrap();
    let buy_min_token_out = buy_quote.amount_out.parse::<u128>().unwrap();
    let buy_fee = required_fee(2, 2);
    assert!(utxos[next_utxo].1.amount > buy_in_sompi + buy_fee);
    let buy_change = utxos[next_utxo].1.amount - buy_in_sompi - buy_fee;
    let buy_tx = build_payload_tx_with_outputs(
        &owner_sk,
        vec![
            (
                TransactionOutpoint::new(pool_before.vault_txid, pool_before.vault_output_index),
                UtxoEntry::new(pool_vault_value, liquidity_vault_script(), 0, false),
                0,
            ),
            (utxos[next_utxo].0, utxos[next_utxo].1.clone(), 1),
        ],
        vec![
            TransactionOutput { value: pool_vault_value + buy_in_sompi, script_public_key: liquidity_vault_script() },
            TransactionOutput { value: buy_change, script_public_key: pay_to_address_script(&owner_address) },
        ],
        payload_buy_liquidity(1, 1, liquidity_asset_bytes, pool_before.pool_nonce, buy_in_sompi, buy_min_token_out),
    );
    token_txids.push(("liquidity-buy-0".to_string(), buy_tx.id()));
    ordered_queued.push(("liquidity-buy-0".to_string(), buy_tx));

    let phase_one_queued = parallel_queued.len() + ordered_queued.len();
    let parallel_submit = tokio::spawn(submit_transactions_parallel_owned(client.clone(), parallel_queued, 16));
    for (label, tx) in &ordered_queued {
        submit_transaction_and_assert_mempool(&client, label, tx).await;
    }
    parallel_submit.await.expect("parallel stress submit task panicked");
    let mempool_entries = client.get_mempool_entries(false, false).await.unwrap();
    assert!(
        mempool_entries.len() >= phase_one_queued,
        "mempool did not retain queued stress load: queued={} entries={}",
        phase_one_queued,
        mempool_entries.len()
    );

    mine_blocks(&client, &owner_address, 1).await;
    for _ in 0..160 {
        let remaining = client.get_mempool_entries(false, false).await.unwrap();
        let mut token_done = true;
        for (_, txid) in &token_txids {
            match client.get_token_op_status_call(None, GetTokenOpStatusRequest { txid: *txid, at_block_hash: None }).await {
                Ok(status) if status.apply_status.is_some() => {}
                Ok(_) => token_done = false,
                Err(_) => token_done = false,
            }
        }
        if remaining.is_empty() && token_done {
            break;
        }
        mine_blocks(&client, &owner_address, 1).await;
    }

    let remaining = client.get_mempool_entries(false, false).await.unwrap();
    assert!(remaining.is_empty(), "phase-one mempool did not drain after stress mining: remaining={}", remaining.len());

    for (label, txid) in &token_txids {
        let status =
            client.get_token_op_status_call(None, GetTokenOpStatusRequest { txid: *txid, at_block_hash: None }).await.unwrap();
        assert_eq!(
            status.apply_status,
            Some(0),
            "unexpected token apply status for {label} tx {txid}: apply_status={:?} noop_reason={:?}",
            status.apply_status,
            status.noop_reason
        );
    }

    let pool_after_buy = client
        .get_liquidity_pool_state_call(
            None,
            GetLiquidityPoolStateRequest { asset_id: liquidity_asset_id.clone(), at_block_hash: None },
        )
        .await
        .unwrap()
        .pool
        .expect("liquidity pool must exist after queued buy");
    assert_eq!(pool_after_buy.pool_nonce, pool_before.pool_nonce + 1);
    let unclaimed_after_buy = pool_after_buy.unclaimed_fee_total_sompi.parse::<u64>().unwrap();
    assert!(unclaimed_after_buy > 0);

    let sell_token_in = 2u128;
    let sell_quote = client
        .get_liquidity_quote_call(
            None,
            GetLiquidityQuoteRequest {
                asset_id: liquidity_asset_id.clone(),
                side: 1,
                exact_in_amount: sell_token_in.to_string(),
                at_block_hash: None,
            },
        )
        .await
        .unwrap();
    let sell_cpay_out = sell_quote.amount_out.parse::<u64>().unwrap();
    let sell_fee = required_fee(2, 3);
    assert!(buy_change > sell_fee);
    let sell_change = buy_change - sell_fee;
    let sell_vault_value = pool_after_buy.vault_value_sompi.parse::<u64>().unwrap() - sell_cpay_out;
    let sell_tx = build_payload_tx_with_outputs(
        &owner_sk,
        vec![
            (
                TransactionOutpoint::new(pool_after_buy.vault_txid, pool_after_buy.vault_output_index),
                UtxoEntry::new(pool_after_buy.vault_value_sompi.parse::<u64>().unwrap(), liquidity_vault_script(), 0, false),
                0,
            ),
            (
                TransactionOutpoint::new(token_txids.last().unwrap().1, 1),
                UtxoEntry::new(buy_change, pay_to_address_script(&owner_address), 0, false),
                1,
            ),
        ],
        vec![
            TransactionOutput { value: sell_vault_value, script_public_key: liquidity_vault_script() },
            TransactionOutput { value: sell_cpay_out, script_public_key: pay_to_address_script(&owner_address) },
            TransactionOutput { value: sell_change, script_public_key: pay_to_address_script(&owner_address) },
        ],
        payload_sell_liquidity(1, 2, liquidity_asset_bytes, pool_after_buy.pool_nonce, sell_token_in, sell_cpay_out, 1),
    );
    let sell_txid = sell_tx.id();
    let claim_amount = 12_000_000u64;
    assert!(
        unclaimed_after_buy >= claim_amount,
        "liquidity buy did not accrue enough claimable fees for a non-dust claim: accrued={unclaimed_after_buy} claim={claim_amount}"
    );
    let claim_fee = required_fee(2, 3);
    assert!(sell_change > claim_fee);
    let claim_change = sell_change - claim_fee;
    let claim_vault_value = sell_vault_value - claim_amount;
    let claim_tx = build_payload_tx_with_outputs(
        &owner_sk,
        vec![
            (TransactionOutpoint::new(sell_txid, 0), UtxoEntry::new(sell_vault_value, liquidity_vault_script(), 0, false), 0),
            (TransactionOutpoint::new(sell_txid, 2), UtxoEntry::new(sell_change, pay_to_address_script(&owner_address), 0, false), 1),
        ],
        vec![
            TransactionOutput { value: claim_vault_value, script_public_key: liquidity_vault_script() },
            TransactionOutput { value: claim_amount, script_public_key: pay_to_address_script(&owner_address) },
            TransactionOutput { value: claim_change, script_public_key: pay_to_address_script(&owner_address) },
        ],
        payload_claim_liquidity(1, 3, liquidity_asset_bytes, pool_after_buy.pool_nonce + 1, 0, claim_amount, 1),
    );
    let pool_chain_txs = vec![("liquidity-sell-0".to_string(), sell_tx), ("liquidity-claim-0".to_string(), claim_tx)];
    for (label, tx) in &pool_chain_txs {
        token_txids.push((label.clone(), tx.id()));
        submit_transaction_and_assert_mempool(&client, label, tx).await;
    }
    let phase_two_mempool = client.get_mempool_entries(false, false).await.unwrap();
    assert!(
        phase_two_mempool.len() >= pool_chain_txs.len(),
        "pool sell/claim chain was not retained in mempool: queued={} entries={}",
        pool_chain_txs.len(),
        phase_two_mempool.len()
    );

    mine_blocks(&client, &owner_address, 1).await;
    for _ in 0..80 {
        let remaining = client.get_mempool_entries(false, false).await.unwrap();
        let mut pool_chain_done = true;
        for (_, txid) in pool_chain_txs.iter().map(|(label, tx)| (label, tx.id())) {
            match client.get_token_op_status_call(None, GetTokenOpStatusRequest { txid, at_block_hash: None }).await {
                Ok(status) if status.apply_status.is_some() => {}
                Ok(_) => pool_chain_done = false,
                Err(_) => pool_chain_done = false,
            }
        }
        if remaining.is_empty() && pool_chain_done {
            break;
        }
        mine_blocks(&client, &owner_address, 1).await;
    }
    let remaining = client.get_mempool_entries(false, false).await.unwrap();
    assert!(remaining.is_empty(), "phase-two mempool did not drain after sell/claim mining: remaining={}", remaining.len());

    for (label, txid) in &token_txids {
        let status =
            client.get_token_op_status_call(None, GetTokenOpStatusRequest { txid: *txid, at_block_hash: None }).await.unwrap();
        assert_eq!(
            status.apply_status,
            Some(0),
            "unexpected token apply status after pool-chain phase for {label} tx {txid}: apply_status={:?} noop_reason={:?}",
            status.apply_status,
            status.noop_reason
        );
    }

    let owner_balance = client
        .get_token_balance_call(
            None,
            GetTokenBalanceRequest { asset_id: base_asset_id.clone(), owner_id: owner_id_hex.clone(), at_block_hash: None },
        )
        .await
        .unwrap();
    assert_eq!(owner_balance.balance, "20720");
    let receiver_balance = client
        .get_token_balance_call(
            None,
            GetTokenBalanceRequest { asset_id: base_asset_id.clone(), owner_id: receiver_id_hex.clone(), at_block_hash: None },
        )
        .await
        .unwrap();
    assert_eq!(receiver_balance.balance, "360");

    let base_asset = client
        .get_token_asset_call(None, GetTokenAssetRequest { asset_id: base_asset_id.clone(), at_block_hash: None })
        .await
        .unwrap()
        .asset
        .expect("base asset must exist after stress run");
    assert_eq!(base_asset.total_supply, "21080");

    let owner_nonce_after = client
        .get_token_nonce_call(None, GetTokenNonceRequest { owner_id: owner_id_hex.clone(), asset_id: None, at_block_hash: None })
        .await
        .unwrap();
    assert_eq!(owner_nonce_after.expected_next_nonce, owner_nonce);
    let base_asset_nonce_after = client
        .get_token_nonce_call(
            None,
            GetTokenNonceRequest { owner_id: owner_id_hex.clone(), asset_id: Some(base_asset_id.clone()), at_block_hash: None },
        )
        .await
        .unwrap();
    assert_eq!(base_asset_nonce_after.expected_next_nonce, asset_nonce);
    let liquidity_asset_nonce_after = client
        .get_token_nonce_call(
            None,
            GetTokenNonceRequest { owner_id: owner_id_hex.clone(), asset_id: Some(liquidity_asset_id.clone()), at_block_hash: None },
        )
        .await
        .unwrap();
    assert_eq!(liquidity_asset_nonce_after.expected_next_nonce, 4);

    let assets = client
        .get_token_assets_call(None, GetTokenAssetsRequest { offset: 0, limit: 100, query: None, at_block_hash: None })
        .await
        .unwrap();
    assert!(assets.total >= 22, "expected stress run to create at least 22 token assets, got {}", assets.total);

    let pool_after = client
        .get_liquidity_pool_state_call(
            None,
            GetLiquidityPoolStateRequest { asset_id: liquidity_asset_id.clone(), at_block_hash: None },
        )
        .await
        .unwrap()
        .pool
        .expect("liquidity pool must exist after queued buy");
    assert_eq!(pool_after.pool_nonce, pool_before.pool_nonce + 3);
    assert!(pool_after.total_supply.parse::<u128>().unwrap() > 0);
    let unclaimed_after_claim = pool_after.unclaimed_fee_total_sompi.parse::<u64>().unwrap();
    assert!(
        unclaimed_after_claim + claim_amount >= unclaimed_after_buy,
        "claim should only reduce available fees by the claimed amount plus/minus later trade fees: after_buy={unclaimed_after_buy} after_claim={unclaimed_after_claim}"
    );
    let liquidity_holders = client
        .get_liquidity_holders_call(
            None,
            GetLiquidityHoldersRequest { asset_id: liquidity_asset_id, offset: 0, limit: 100, at_block_hash: None },
        )
        .await
        .unwrap();
    assert!(liquidity_holders.total >= 1);

    let events = client
        .get_token_events_call(None, GetTokenEventsRequest { after_sequence: 0, limit: 2000, at_block_hash: None })
        .await
        .unwrap();
    assert!(
        events.events.len() >= token_txids.len() + 2,
        "expected at least all setup and stress token events, got {} for {} queued token txs",
        events.events.len(),
        token_txids.len()
    );

    let state_hash_before = client.get_token_state_hash_call(None, GetTokenStateHashRequest { at_block_hash: None }).await.unwrap();
    let snapshot_dir = tempfile::tempdir().unwrap();
    let snapshot_path: PathBuf = snapshot_dir.path().join("atomic-mempool-stress.snapshot");
    client
        .export_token_snapshot_call(None, ExportTokenSnapshotRequest { path: snapshot_path.to_string_lossy().to_string() })
        .await
        .unwrap();
    client
        .import_token_snapshot_call(None, ImportTokenSnapshotRequest { path: snapshot_path.to_string_lossy().to_string() })
        .await
        .unwrap();
    let state_hash_after = client.get_token_state_hash_call(None, GetTokenStateHashRequest { at_block_hash: None }).await.unwrap();
    assert_eq!(state_hash_after.context.state_hash, state_hash_before.context.state_hash);

    let health = client.get_token_health_call(None, GetTokenHealthRequest { at_block_hash: None }).await.unwrap();
    assert_eq!(health.token_state, "healthy");
    assert!(!health.is_degraded);
    assert!(!health.bootstrap_in_progress);
    assert!(health.live_correct);
    assert_eq!(health.state_hash, state_hash_before.context.state_hash);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "long-running full-chain stress test; run with --ignored and optionally CRYPTIX_STRESS_SECONDS=600"]
async fn atomic_token_ignored_long_full_chain_stress_mempool_blocks_and_state() {
    cryptix_core::log::try_init_logger("INFO");
    let stress_duration = stress_duration_from_env();
    let mut daemon = Daemon::new_random_with_args(atomic_args(), 10);
    let client = daemon.start().await;
    let consensus_manager = consensus_manager_from_daemon(&daemon);

    let (owner_sk, owner_pk) = secp256k1::generate_keypair(&mut thread_rng());
    let owner_address = Address::new(daemon.network.into(), Version::PubKey, &owner_pk.x_only_public_key().0.serialize());
    let (_receiver_sk, receiver_pk) = secp256k1::generate_keypair(&mut thread_rng());
    let receiver_address = Address::new(daemon.network.into(), Version::PubKey, &receiver_pk.x_only_public_key().0.serialize());
    let mut stress_wallets = Vec::with_capacity(ATOMIC_LONG_STRESS_WALLET_COUNT);
    for wallet_index in 0..ATOMIC_LONG_STRESS_WALLET_COUNT {
        let (secret, public) = secp256k1::generate_keypair(&mut thread_rng());
        let pubkey_bytes = public.x_only_public_key().0.serialize();
        let address = Address::new(daemon.network.into(), Version::PubKey, &pubkey_bytes);
        let owner_id = owner_id_from_address(&address);
        stress_wallets.push(StressWallet {
            label: format!("wallet-{wallet_index}"),
            secret,
            address,
            owner_id,
            owner_id_hex: hex32(owner_id),
            pubkey_bytes,
            queue: VecDeque::new(),
            consumed_outpoints: HashSet::new(),
            owner_nonce: 1,
            expected_base_balance: 0,
        });
    }
    let owner_pubkey_bytes = owner_pk.x_only_public_key().0.serialize();
    let owner_id = owner_id_from_address(&owner_address);
    let receiver_id = owner_id_from_address(&receiver_address);
    let owner_id_hex = hex32(owner_id);
    let receiver_id_hex = hex32(receiver_id);
    let owner_keypair = || Keypair::from_secret_key(secp256k1::SECP256K1, &owner_sk);
    let coinbase_maturity = daemon.args.read().coinbase_maturity_override.unwrap_or(SIMNET_PARAMS.coinbase_maturity);

    let initial_utxos = mine_until_spendable_utxos(&client, &owner_address, coinbase_maturity, 260).await;
    let mut utxo_queue: VecDeque<_> = initial_utxos.into_iter().collect();
    let mut consumed_outpoints = HashSet::new();
    let mut accepted_producer_txids = HashSet::new();
    let mut token_txids = Vec::new();

    let wallet_funding_chain_start = client.get_block_dag_info().await.unwrap().sink;
    let mut wallet_funding_txs = Vec::with_capacity(stress_wallets.len());
    let mut wallet_funding_traces = Vec::with_capacity(stress_wallets.len());
    for wallet in &stress_wallets {
        let funding_utxo = pop_stress_utxo(&mut utxo_queue, &mut consumed_outpoints, "stress wallet funding");
        let funding_tx = build_stress_wallet_funding_tx(
            owner_keypair(),
            &funding_utxo,
            &wallet.address,
            &owner_address,
            ATOMIC_LONG_STRESS_WALLET_FUNDING_OUTPUTS,
        );
        let label = format!("long-fund-{}", wallet.label);
        wallet_funding_traces.push(stress_tx_trace(
            label.clone(),
            funding_tx.id(),
            vec![funding_utxo.clone()],
            &accepted_producer_txids,
        ));
        wallet_funding_txs.push((label, funding_tx));
    }
    submit_transactions_parallel_owned(client.clone(), wallet_funding_txs, ATOMIC_LONG_STRESS_WALLET_COUNT).await;
    let _ = drain_stress_mempool(&client, &owner_address, "long stress wallet funding").await;
    let wallet_funding_accepted =
        assert_txids_accepted_since(&client, wallet_funding_chain_start, &wallet_funding_traces, "long stress wallet funding").await;
    accepted_producer_txids.extend(wallet_funding_accepted);
    for wallet in &mut stress_wallets {
        refill_stress_utxos(
            &client,
            consensus_manager.as_ref(),
            &wallet.address,
            coinbase_maturity,
            &mut wallet.queue,
            &wallet.consumed_outpoints,
            &accepted_producer_txids,
            ATOMIC_LONG_STRESS_WALLET_FUNDING_OUTPUTS,
        )
        .await;
    }

    let base_create_utxo = pop_stress_utxo(&mut utxo_queue, &mut consumed_outpoints, "base asset create");
    let base_create_tx = build_stress_payload_tx(
        owner_keypair(),
        &base_create_utxo,
        &owner_address,
        payload_create_asset_with_mint(
            0,
            1,
            2,
            20_000_000,
            owner_id,
            owner_id,
            250_000,
            b"LongStressBase",
            b"LSB",
            b"long-stress-base",
        ),
    );
    submit_and_wait_indexed(&client, &base_create_tx, &owner_address).await;
    accepted_producer_txids.insert(base_create_tx.id());
    token_txids.push(("setup-base-create".to_string(), base_create_tx.id()));
    let base_asset_id = base_create_tx.id().to_string();
    let base_asset_bytes = base_create_tx.id().as_bytes();

    let liquidity_utxo = pop_stress_utxo(&mut utxo_queue, &mut consumed_outpoints, "liquidity asset create");
    let liquidity_vault_value = MIN_LIQUIDITY_SEED_RESERVE_SOMPI;
    let liquidity_fee = required_fee(1, 2);
    assert!(liquidity_utxo.1.amount > liquidity_vault_value + liquidity_fee);
    let liquidity_change = liquidity_utxo.1.amount - liquidity_vault_value - liquidity_fee;
    let liquidity_create_tx = build_payload_tx_with_outputs(
        &owner_sk,
        vec![(liquidity_utxo.0, liquidity_utxo.1.clone(), 1)],
        vec![
            TransactionOutput { value: liquidity_vault_value, script_public_key: liquidity_vault_script() },
            TransactionOutput { value: liquidity_change, script_public_key: pay_to_address_script(&owner_address) },
        ],
        payload_create_liquidity_with_fee_recipient(
            0,
            2,
            LIQUIDITY_TOKEN_SUPPLY_RAW,
            100,
            &owner_address,
            0,
            0,
            b"LongStressPool",
            b"LSP",
        ),
    );
    submit_and_wait_indexed(&client, &liquidity_create_tx, &owner_address).await;
    accepted_producer_txids.insert(liquidity_create_tx.id());
    token_txids.push(("setup-liquidity-create".to_string(), liquidity_create_tx.id()));
    let liquidity_asset_id = liquidity_create_tx.id().to_string();
    let liquidity_asset_bytes = liquidity_create_tx.id().as_bytes();

    let initial_pool = client
        .get_liquidity_pool_state_call(
            None,
            GetLiquidityPoolStateRequest { asset_id: liquidity_asset_id.clone(), at_block_hash: None },
        )
        .await
        .unwrap()
        .pool
        .expect("liquidity pool must exist before long stress");
    assert_eq!(initial_pool.pool_nonce, 1);

    let mut owner_nonce = 3u64;
    let mut base_asset_nonce = 1u64;
    let mut liquidity_asset_nonce = 1u64;
    let mut expected_pool_nonce = 1u64;
    let mut expected_owner_base_balance = 250_000u128;
    let mut expected_receiver_base_balance = 0u128;
    let mut expected_base_supply = 250_000u128;
    let mut created_assets = Vec::<(String, String, String, String, u128)>::new();
    let mut submitted_native = 0usize;
    let mut submitted_messenger = 0usize;
    let mut submitted_raw_payloads = 0usize;
    let mut submitted_token_creates = 0usize;
    let mut submitted_wallet_native = 0usize;
    let mut submitted_wallet_messenger = 0usize;
    let mut submitted_wallet_raw_payloads = 0usize;
    let mut submitted_wallet_token_creates = 0usize;
    let mut submitted_base_ops = 0usize;
    let mut submitted_liquidity_buys = 0usize;
    let mut submitted_liquidity_sells = 0usize;
    let mut submitted_liquidity_claims = 0usize;
    let mut active_stress_wallets = HashSet::new();
    let mut max_mempool_entries = 0usize;
    let mut max_block_template_txs = 0usize;
    let mut mined_stress_blocks = 0u64;
    let stress_started = Instant::now();
    let mut round = 0u64;
    let stress_addresses = stress_wallets.iter().map(|wallet| wallet.address.clone()).collect::<Vec<_>>();
    let stress_owner_ids = stress_wallets.iter().map(|wallet| wallet.owner_id).collect::<Vec<_>>();

    while stress_started.elapsed() < stress_duration || round == 0 {
        refill_stress_utxos(
            &client,
            consensus_manager.as_ref(),
            &owner_address,
            coinbase_maturity,
            &mut utxo_queue,
            &consumed_outpoints,
            &accepted_producer_txids,
            100,
        )
        .await;
        for wallet in &mut stress_wallets {
            refill_stress_utxos(
                &client,
                consensus_manager.as_ref(),
                &wallet.address,
                coinbase_maturity,
                &mut wallet.queue,
                &wallet.consumed_outpoints,
                &accepted_producer_txids,
                ATOMIC_LONG_STRESS_WALLET_MIN_UTXOS,
            )
            .await;
        }

        let mut parallel_queued = Vec::new();
        let mut ordered_queued = Vec::new();
        let mut phase_token_txids = Vec::new();
        let mut phase_all_txids = Vec::new();

        for i in 0..20u64 {
            let utxo = pop_stress_utxo(&mut utxo_queue, &mut consumed_outpoints, "native stress tx");
            let tx = build_stress_native_tx(owner_keypair(), &utxo, &owner_address);
            let label = format!("long-native-{round}-{i}");
            phase_all_txids.push(stress_tx_trace(label.clone(), tx.id(), vec![utxo.clone()], &accepted_producer_txids));
            parallel_queued.push((label, tx));
            submitted_native += 1;
        }

        for i in 0..20u64 {
            let utxo = pop_stress_utxo(&mut utxo_queue, &mut consumed_outpoints, "messenger stress tx");
            let body_len = 96 + (((round + i) % 5) as usize * 64);
            let tx = build_stress_payload_tx(
                owner_keypair(),
                &utxo,
                &owner_address,
                messenger_payload_v1(round * 10_000 + i, owner_pubkey_bytes, body_len),
            );
            let label = format!("long-messenger-{round}-{i}");
            phase_all_txids.push(stress_tx_trace(label.clone(), tx.id(), vec![utxo.clone()], &accepted_producer_txids));
            parallel_queued.push((label, tx));
            submitted_messenger += 1;
        }

        for i in 0..10u64 {
            let utxo = pop_stress_utxo(&mut utxo_queue, &mut consumed_outpoints, "raw payload stress tx");
            let mut payload = format!("RAW:long-stress:{round}:{i}:").into_bytes();
            payload.resize(240 + (((round + i) % 4) as usize * 64), (round.wrapping_add(i) & 0xff) as u8);
            let tx = build_stress_payload_tx(owner_keypair(), &utxo, &owner_address, payload);
            let label = format!("long-raw-payload-{round}-{i}");
            phase_all_txids.push(stress_tx_trace(label.clone(), tx.id(), vec![utxo.clone()], &accepted_producer_txids));
            parallel_queued.push((label, tx));
            submitted_raw_payloads += 1;
        }

        for wallet_index in 0..stress_wallets.len() {
            let recipient_index = (wallet_index + round as usize + 1) % stress_addresses.len();
            let wallet = &mut stress_wallets[wallet_index];
            let utxo = pop_stress_utxo(&mut wallet.queue, &mut wallet.consumed_outpoints, "multi-wallet native stress tx");
            let tx = build_stress_native_tx(wallet.keypair(), &utxo, &stress_addresses[recipient_index]);
            let label = format!("long-wallet-native-{round}-{wallet_index}");
            phase_all_txids.push(stress_tx_trace(label.clone(), tx.id(), vec![utxo.clone()], &accepted_producer_txids));
            parallel_queued.push((label, tx));
            active_stress_wallets.insert(wallet.owner_id_hex.clone());
            submitted_native += 1;
            submitted_wallet_native += 1;
        }

        for wallet_index in 0..stress_wallets.len() {
            let recipient_index = (wallet_index + round as usize + 2) % stress_addresses.len();
            let wallet = &mut stress_wallets[wallet_index];
            let utxo = pop_stress_utxo(&mut wallet.queue, &mut wallet.consumed_outpoints, "multi-wallet messenger stress tx");
            let body_len = 128 + (((round + wallet_index as u64) % 7) as usize * 48);
            let tx = build_stress_payload_tx(
                wallet.keypair(),
                &utxo,
                &stress_addresses[recipient_index],
                messenger_payload_v1(round * 100_000 + wallet_index as u64, wallet.pubkey_bytes, body_len),
            );
            let label = format!("long-wallet-messenger-{round}-{wallet_index}");
            phase_all_txids.push(stress_tx_trace(label.clone(), tx.id(), vec![utxo.clone()], &accepted_producer_txids));
            parallel_queued.push((label, tx));
            active_stress_wallets.insert(wallet.owner_id_hex.clone());
            submitted_messenger += 1;
            submitted_wallet_messenger += 1;
        }

        for wallet_index in 0..stress_wallets.len() {
            let recipient_index = (wallet_index + round as usize + 3) % stress_addresses.len();
            let wallet = &mut stress_wallets[wallet_index];
            let utxo = pop_stress_utxo(&mut wallet.queue, &mut wallet.consumed_outpoints, "multi-wallet raw payload stress tx");
            let mut payload = format!("RAW:multi-wallet:{round}:{wallet_index}:").into_bytes();
            payload.resize(160 + (((round + wallet_index as u64) % 6) as usize * 80), (wallet_index as u8).wrapping_add(round as u8));
            let tx = build_stress_payload_tx(wallet.keypair(), &utxo, &stress_addresses[recipient_index], payload);
            let label = format!("long-wallet-raw-payload-{round}-{wallet_index}");
            phase_all_txids.push(stress_tx_trace(label.clone(), tx.id(), vec![utxo.clone()], &accepted_producer_txids));
            parallel_queued.push((label, tx));
            active_stress_wallets.insert(wallet.owner_id_hex.clone());
            submitted_raw_payloads += 1;
            submitted_wallet_raw_payloads += 1;
        }

        for i in 0..6u64 {
            let utxo = pop_stress_utxo(&mut utxo_queue, &mut consumed_outpoints, "stress token create");
            let initial_mint = 1_000u128 + u128::from(round * 6 + i);
            let name = format!("LongStress{round:04}{i:02}");
            let symbol = format!("L{round:04}{i:02}");
            let tx = build_stress_payload_tx(
                owner_keypair(),
                &utxo,
                &owner_address,
                payload_create_asset_with_mint(
                    0,
                    owner_nonce,
                    0,
                    1_000_000_000,
                    owner_id,
                    owner_id,
                    initial_mint,
                    name.as_bytes(),
                    symbol.as_bytes(),
                    b"long-stress-created",
                ),
            );
            owner_nonce += 1;
            let label = format!("long-create-{round}-{i}");
            let txid = tx.id();
            token_txids.push((label.clone(), txid));
            phase_token_txids.push((label.clone(), txid));
            phase_all_txids.push(stress_tx_trace(label.clone(), txid, vec![utxo.clone()], &accepted_producer_txids));
            created_assets.push((txid.to_string(), name, symbol, owner_id_hex.clone(), initial_mint));
            ordered_queued.push((label, tx));
            submitted_token_creates += 1;
        }

        for i in 0..ATOMIC_LONG_STRESS_WALLET_TOKEN_CREATES_PER_ROUND {
            let wallet_index = (round as usize + i as usize) % stress_wallets.len();
            let wallet = &mut stress_wallets[wallet_index];
            let utxo = pop_stress_utxo(&mut wallet.queue, &mut wallet.consumed_outpoints, "multi-wallet token create");
            let initial_mint = 700u128 + u128::from(round * ATOMIC_LONG_STRESS_WALLET_TOKEN_CREATES_PER_ROUND + i);
            let name = format!("WalletStress{wallet_index:02}{round:04}{i:02}");
            let symbol = format!("W{wallet_index:02}{round:04}{i:02}");
            let tx = build_stress_payload_tx(
                wallet.keypair(),
                &utxo,
                &wallet.address,
                payload_create_asset_with_mint(
                    0,
                    wallet.owner_nonce,
                    0,
                    500_000_000,
                    wallet.owner_id,
                    wallet.owner_id,
                    initial_mint,
                    name.as_bytes(),
                    symbol.as_bytes(),
                    b"long-stress-wallet-created",
                ),
            );
            wallet.owner_nonce += 1;
            let label = format!("long-wallet-create-{round}-{wallet_index}-{i}");
            let txid = tx.id();
            token_txids.push((label.clone(), txid));
            phase_token_txids.push((label.clone(), txid));
            phase_all_txids.push(stress_tx_trace(label.clone(), txid, vec![utxo.clone()], &accepted_producer_txids));
            created_assets.push((txid.to_string(), name, symbol, wallet.owner_id_hex.clone(), initial_mint));
            ordered_queued.push((label, tx));
            active_stress_wallets.insert(wallet.owner_id_hex.clone());
            submitted_token_creates += 1;
            submitted_wallet_token_creates += 1;
        }

        for i in 0..8u64 {
            let mint_amount = 40u128 + u128::from((round + i) % 17);
            let transfer_amount = 9u128 + u128::from((round + i) % 5);
            let burn_amount = 4u128 + u128::from((round + i) % 3);

            let mint_utxo = pop_stress_utxo(&mut utxo_queue, &mut consumed_outpoints, "stress token mint");
            let mint_tx = build_stress_payload_tx(
                owner_keypair(),
                &mint_utxo,
                &owner_address,
                payload_mint(0, base_asset_nonce, base_asset_bytes, owner_id, mint_amount),
            );
            base_asset_nonce += 1;
            expected_owner_base_balance += mint_amount;
            expected_base_supply += mint_amount;
            let mint_label = format!("long-mint-{round}-{i}");
            let mint_txid = mint_tx.id();
            token_txids.push((mint_label.clone(), mint_txid));
            phase_token_txids.push((mint_label.clone(), mint_txid));
            phase_all_txids.push(stress_tx_trace(mint_label.clone(), mint_txid, vec![mint_utxo.clone()], &accepted_producer_txids));
            ordered_queued.push((mint_label, mint_tx));
            submitted_base_ops += 1;

            let transfer_utxo = pop_stress_utxo(&mut utxo_queue, &mut consumed_outpoints, "stress token transfer");
            let recipient_slot = ((round + i) as usize) % (stress_owner_ids.len() + 1);
            let transfer_recipient = if recipient_slot == 0 { receiver_id } else { stress_owner_ids[recipient_slot - 1] };
            let transfer_tx = build_stress_payload_tx(
                owner_keypair(),
                &transfer_utxo,
                &owner_address,
                payload_transfer(0, base_asset_nonce, base_asset_bytes, transfer_recipient, transfer_amount),
            );
            base_asset_nonce += 1;
            expected_owner_base_balance -= transfer_amount;
            if recipient_slot == 0 {
                expected_receiver_base_balance += transfer_amount;
            } else {
                stress_wallets[recipient_slot - 1].expected_base_balance += transfer_amount;
            }
            let transfer_label = format!("long-transfer-{round}-{i}");
            let transfer_txid = transfer_tx.id();
            token_txids.push((transfer_label.clone(), transfer_txid));
            phase_token_txids.push((transfer_label.clone(), transfer_txid));
            phase_all_txids.push(stress_tx_trace(
                transfer_label.clone(),
                transfer_txid,
                vec![transfer_utxo.clone()],
                &accepted_producer_txids,
            ));
            ordered_queued.push((transfer_label, transfer_tx));
            submitted_base_ops += 1;

            let burn_utxo = pop_stress_utxo(&mut utxo_queue, &mut consumed_outpoints, "stress token burn");
            let burn_tx = build_stress_payload_tx(
                owner_keypair(),
                &burn_utxo,
                &owner_address,
                payload_burn(0, base_asset_nonce, base_asset_bytes, burn_amount),
            );
            base_asset_nonce += 1;
            expected_owner_base_balance -= burn_amount;
            expected_base_supply -= burn_amount;
            let burn_label = format!("long-burn-{round}-{i}");
            let burn_txid = burn_tx.id();
            token_txids.push((burn_label.clone(), burn_txid));
            phase_token_txids.push((burn_label.clone(), burn_txid));
            phase_all_txids.push(stress_tx_trace(burn_label.clone(), burn_txid, vec![burn_utxo.clone()], &accepted_producer_txids));
            ordered_queued.push((burn_label, burn_tx));
            submitted_base_ops += 1;
        }

        let pool_before_buy = client
            .get_liquidity_pool_state_call(
                None,
                GetLiquidityPoolStateRequest { asset_id: liquidity_asset_id.clone(), at_block_hash: None },
            )
            .await
            .unwrap()
            .pool
            .expect("liquidity pool must exist before stress buy");
        assert_eq!(pool_before_buy.pool_nonce, expected_pool_nonce);
        let pool_vault_value = pool_before_buy.vault_value_sompi.parse::<u64>().unwrap();
        let buy_quote = client
            .get_liquidity_quote_call(
                None,
                GetLiquidityQuoteRequest {
                    asset_id: liquidity_asset_id.clone(),
                    side: 0,
                    exact_in_amount: "2000000000".to_string(),
                    at_block_hash: None,
                },
            )
            .await
            .unwrap();
        let buy_in_sompi = buy_quote.exact_in_amount.parse::<u64>().unwrap();
        let buy_min_token_out = buy_quote.amount_out.parse::<u128>().unwrap();
        assert!(buy_min_token_out > 2);
        let buy_fee = required_fee(2, 2);
        let buy_utxo =
            pop_stress_utxo_with_min_amount(&mut utxo_queue, &mut consumed_outpoints, "stress liquidity buy", buy_in_sompi + buy_fee);
        assert!(buy_utxo.1.amount > buy_in_sompi + buy_fee);
        let buy_change = buy_utxo.1.amount - buy_in_sompi - buy_fee;
        let buy_vault_input = (
            TransactionOutpoint::new(pool_before_buy.vault_txid, pool_before_buy.vault_output_index),
            UtxoEntry::new(pool_vault_value, liquidity_vault_script(), 0, false),
        );
        let buy_tx = build_payload_tx_with_outputs(
            &owner_sk,
            vec![(buy_vault_input.0, buy_vault_input.1.clone(), 0), (buy_utxo.0, buy_utxo.1.clone(), 1)],
            vec![
                TransactionOutput { value: pool_vault_value + buy_in_sompi, script_public_key: liquidity_vault_script() },
                TransactionOutput { value: buy_change, script_public_key: pay_to_address_script(&owner_address) },
            ],
            payload_buy_liquidity(
                1,
                liquidity_asset_nonce,
                liquidity_asset_bytes,
                pool_before_buy.pool_nonce,
                buy_in_sompi,
                buy_min_token_out,
            ),
        );
        let buy_txid = buy_tx.id();
        liquidity_asset_nonce += 1;
        expected_pool_nonce += 1;
        let buy_label = format!("long-liquidity-buy-{round}");
        token_txids.push((buy_label.clone(), buy_txid));
        phase_token_txids.push((buy_label.clone(), buy_txid));
        phase_all_txids.push(stress_tx_trace(
            buy_label.clone(),
            buy_txid,
            vec![buy_vault_input, buy_utxo.clone()],
            &accepted_producer_txids,
        ));
        ordered_queued.push((buy_label, buy_tx));
        submitted_liquidity_buys += 1;

        let phase_queued = parallel_queued.len() + ordered_queued.len();
        let parallel_submit = tokio::spawn(submit_transactions_parallel_owned(client.clone(), parallel_queued, 32));
        for (label, tx) in &ordered_queued {
            submit_transaction_and_assert_mempool(&client, label, tx).await;
        }
        parallel_submit.await.expect("long stress parallel submit task panicked");
        let phase_mempool = client.get_mempool_entries(false, false).await.unwrap();
        max_mempool_entries = max_mempool_entries.max(phase_mempool.len());
        assert!(
            phase_mempool.len() >= phase_queued,
            "long stress phase did not retain queued load: round={round} queued={phase_queued} entries={}",
            phase_mempool.len()
        );

        let phase_chain_start = client.get_block_dag_info().await.unwrap().sink;
        let (phase_max_block_txs, phase_mined_blocks) = drain_stress_mempool(&client, &owner_address, "long stress phase").await;
        max_block_template_txs = max_block_template_txs.max(phase_max_block_txs);
        mined_stress_blocks += phase_mined_blocks;
        let phase_accepted =
            assert_txids_accepted_since(&client, phase_chain_start, &phase_all_txids, &format!("long stress phase {round}")).await;
        accepted_producer_txids.extend(phase_accepted);
        assert_token_statuses_applied(&client, &phase_token_txids, &format!("long stress phase {round}")).await;

        let pool_after_buy = client
            .get_liquidity_pool_state_call(
                None,
                GetLiquidityPoolStateRequest { asset_id: liquidity_asset_id.clone(), at_block_hash: None },
            )
            .await
            .unwrap()
            .pool
            .expect("liquidity pool must exist after stress buy");
        assert_eq!(pool_after_buy.pool_nonce, expected_pool_nonce);
        let sell_token_in = 2u128;
        let sell_quote = client
            .get_liquidity_quote_call(
                None,
                GetLiquidityQuoteRequest {
                    asset_id: liquidity_asset_id.clone(),
                    side: 1,
                    exact_in_amount: sell_token_in.to_string(),
                    at_block_hash: None,
                },
            )
            .await
            .unwrap();
        let sell_cpay_out = sell_quote.amount_out.parse::<u64>().unwrap();
        assert!(sell_cpay_out > 0);
        let sell_fee = required_fee(2, 3);
        assert!(buy_change > sell_fee);
        let sell_change = buy_change - sell_fee;
        let sell_vault_value = pool_after_buy.vault_value_sompi.parse::<u64>().unwrap() - sell_cpay_out;
        let sell_vault_input = (
            TransactionOutpoint::new(pool_after_buy.vault_txid, pool_after_buy.vault_output_index),
            UtxoEntry::new(pool_after_buy.vault_value_sompi.parse::<u64>().unwrap(), liquidity_vault_script(), 0, false),
        );
        let sell_change_input =
            (TransactionOutpoint::new(buy_txid, 1), UtxoEntry::new(buy_change, pay_to_address_script(&owner_address), 0, false));
        let sell_tx = build_payload_tx_with_outputs(
            &owner_sk,
            vec![(sell_vault_input.0, sell_vault_input.1.clone(), 0), (sell_change_input.0, sell_change_input.1.clone(), 1)],
            vec![
                TransactionOutput { value: sell_vault_value, script_public_key: liquidity_vault_script() },
                TransactionOutput { value: sell_cpay_out, script_public_key: pay_to_address_script(&owner_address) },
                TransactionOutput { value: sell_change, script_public_key: pay_to_address_script(&owner_address) },
            ],
            payload_sell_liquidity(
                1,
                liquidity_asset_nonce,
                liquidity_asset_bytes,
                pool_after_buy.pool_nonce,
                sell_token_in,
                sell_cpay_out,
                1,
            ),
        );
        let sell_txid = sell_tx.id();
        liquidity_asset_nonce += 1;
        expected_pool_nonce += 1;
        let sell_label = format!("long-liquidity-sell-{round}");
        token_txids.push((sell_label.clone(), sell_txid));
        let sell_change_outpoint = sell_change_input.0;
        let sell_phase_txids =
            vec![stress_tx_trace(sell_label.clone(), sell_txid, vec![sell_vault_input, sell_change_input], &accepted_producer_txids)];
        consumed_outpoints.insert(sell_change_outpoint);
        let sell_phase_token_txids = vec![(sell_label.clone(), sell_txid)];
        submit_transaction_and_assert_mempool(&client, &sell_label, &sell_tx).await;
        submitted_liquidity_sells += 1;
        let sell_mempool = client.get_mempool_entries(false, false).await.unwrap();
        max_mempool_entries = max_mempool_entries.max(sell_mempool.len());
        let sell_chain_start = client.get_block_dag_info().await.unwrap().sink;
        let (sell_max_block_txs, sell_mined_blocks) = drain_stress_mempool(&client, &owner_address, "long stress sell").await;
        max_block_template_txs = max_block_template_txs.max(sell_max_block_txs);
        mined_stress_blocks += sell_mined_blocks;
        let sell_accepted =
            assert_txids_accepted_since(&client, sell_chain_start, &sell_phase_txids, &format!("long stress sell {round}")).await;
        accepted_producer_txids.extend(sell_accepted);
        assert_token_statuses_applied(&client, &sell_phase_token_txids, &format!("long stress sell {round}")).await;

        let pool_after_sell = client
            .get_liquidity_pool_state_call(
                None,
                GetLiquidityPoolStateRequest { asset_id: liquidity_asset_id.clone(), at_block_hash: None },
            )
            .await
            .unwrap()
            .pool
            .expect("liquidity pool must exist after stress sell");
        assert_eq!(pool_after_sell.pool_nonce, expected_pool_nonce);
        let unclaimed_after_sell = pool_after_sell.unclaimed_fee_total_sompi.parse::<u64>().unwrap();
        if round % 3 == 0 && unclaimed_after_sell >= 12_000_000 {
            let claim_amount = 12_000_000u64;
            let claim_fee = required_fee(2, 3);
            assert!(sell_change > claim_fee);
            let claim_change = sell_change - claim_fee;
            let claim_vault_value = pool_after_sell.vault_value_sompi.parse::<u64>().unwrap() - claim_amount;
            let claim_vault_input = (
                TransactionOutpoint::new(pool_after_sell.vault_txid, pool_after_sell.vault_output_index),
                UtxoEntry::new(pool_after_sell.vault_value_sompi.parse::<u64>().unwrap(), liquidity_vault_script(), 0, false),
            );
            let claim_change_input =
                (TransactionOutpoint::new(sell_txid, 2), UtxoEntry::new(sell_change, pay_to_address_script(&owner_address), 0, false));
            let claim_tx = build_payload_tx_with_outputs(
                &owner_sk,
                vec![(claim_vault_input.0, claim_vault_input.1.clone(), 0), (claim_change_input.0, claim_change_input.1.clone(), 1)],
                vec![
                    TransactionOutput { value: claim_vault_value, script_public_key: liquidity_vault_script() },
                    TransactionOutput { value: claim_amount, script_public_key: pay_to_address_script(&owner_address) },
                    TransactionOutput { value: claim_change, script_public_key: pay_to_address_script(&owner_address) },
                ],
                payload_claim_liquidity(
                    1,
                    liquidity_asset_nonce,
                    liquidity_asset_bytes,
                    pool_after_sell.pool_nonce,
                    0,
                    claim_amount,
                    1,
                ),
            );
            liquidity_asset_nonce += 1;
            expected_pool_nonce += 1;
            let claim_label = format!("long-liquidity-claim-{round}");
            token_txids.push((claim_label.clone(), claim_tx.id()));
            let claim_change_outpoint = claim_change_input.0;
            let claim_phase_txids = vec![stress_tx_trace(
                claim_label.clone(),
                claim_tx.id(),
                vec![claim_vault_input, claim_change_input],
                &accepted_producer_txids,
            )];
            consumed_outpoints.insert(claim_change_outpoint);
            let claim_phase_token_txids = vec![(claim_label.clone(), claim_tx.id())];
            submit_transaction_and_assert_mempool(&client, &claim_label, &claim_tx).await;
            submitted_liquidity_claims += 1;
            let claim_mempool = client.get_mempool_entries(false, false).await.unwrap();
            max_mempool_entries = max_mempool_entries.max(claim_mempool.len());
            let claim_chain_start = client.get_block_dag_info().await.unwrap().sink;
            let (claim_max_block_txs, claim_mined_blocks) = drain_stress_mempool(&client, &owner_address, "long stress claim").await;
            max_block_template_txs = max_block_template_txs.max(claim_max_block_txs);
            mined_stress_blocks += claim_mined_blocks;
            let claim_accepted =
                assert_txids_accepted_since(&client, claim_chain_start, &claim_phase_txids, &format!("long stress claim {round}"))
                    .await;
            accepted_producer_txids.extend(claim_accepted);
            assert_token_statuses_applied(&client, &claim_phase_token_txids, &format!("long stress claim {round}")).await;

            let pool_after_claim = client
                .get_liquidity_pool_state_call(
                    None,
                    GetLiquidityPoolStateRequest { asset_id: liquidity_asset_id.clone(), at_block_hash: None },
                )
                .await
                .unwrap()
                .pool
                .expect("liquidity pool must exist after stress claim");
            assert_eq!(pool_after_claim.pool_nonce, expected_pool_nonce);
        }

        round += 1;
    }

    let remaining = client.get_mempool_entries(false, false).await.unwrap();
    assert!(remaining.is_empty(), "long stress ended with non-empty mempool: remaining={}", remaining.len());
    assert!(round > 0, "long stress must execute at least one round");
    assert!(max_mempool_entries >= 70, "expected sustained mempool pressure, max entries={max_mempool_entries}");
    assert!(max_block_template_txs >= 50, "expected stress blocks with many transactions, max block txs={max_block_template_txs}");
    assert!(mined_stress_blocks >= round, "expected at least one mined stress block per round");
    assert!(submitted_native > 0);
    assert!(submitted_messenger > 0);
    assert!(submitted_raw_payloads > 0);
    assert!(submitted_token_creates > 0);
    assert_eq!(
        active_stress_wallets.len(),
        stress_wallets.len(),
        "expected every stress wallet to submit transactions: active={} total={}",
        active_stress_wallets.len(),
        stress_wallets.len()
    );
    assert!(submitted_wallet_native > 0);
    assert!(submitted_wallet_messenger > 0);
    assert!(submitted_wallet_raw_payloads > 0);
    assert!(submitted_wallet_token_creates > 0);
    assert!(submitted_base_ops > 0);
    assert!(submitted_liquidity_buys > 0);
    assert!(submitted_liquidity_sells > 0);
    assert!(submitted_liquidity_claims > 0);

    println!(
        "long stress summary: duration_secs={} rounds={} wallets={} active_wallets={} native={} wallet_native={} messenger={} wallet_messenger={} raw_payloads={} wallet_raw_payloads={} token_creates={} wallet_token_creates={} base_ops={} buys={} sells={} claims={} max_mempool_entries={} max_block_template_txs={} mined_stress_blocks={}",
        stress_duration.as_secs(),
        round,
        stress_wallets.len(),
        active_stress_wallets.len(),
        submitted_native,
        submitted_wallet_native,
        submitted_messenger,
        submitted_wallet_messenger,
        submitted_raw_payloads,
        submitted_wallet_raw_payloads,
        submitted_token_creates,
        submitted_wallet_token_creates,
        submitted_base_ops,
        submitted_liquidity_buys,
        submitted_liquidity_sells,
        submitted_liquidity_claims,
        max_mempool_entries,
        max_block_template_txs,
        mined_stress_blocks
    );
    assert_token_statuses_applied(&client, &token_txids, "long full-chain stress").await;

    let owner_balance = client
        .get_token_balance_call(
            None,
            GetTokenBalanceRequest { asset_id: base_asset_id.clone(), owner_id: owner_id_hex.clone(), at_block_hash: None },
        )
        .await
        .unwrap();
    assert_eq!(owner_balance.balance, expected_owner_base_balance.to_string());
    let receiver_balance = client
        .get_token_balance_call(
            None,
            GetTokenBalanceRequest { asset_id: base_asset_id.clone(), owner_id: receiver_id_hex.clone(), at_block_hash: None },
        )
        .await
        .unwrap();
    assert_eq!(receiver_balance.balance, expected_receiver_base_balance.to_string());
    let base_asset = client
        .get_token_asset_call(None, GetTokenAssetRequest { asset_id: base_asset_id.clone(), at_block_hash: None })
        .await
        .unwrap()
        .asset
        .expect("base asset must exist after long stress");
    assert_eq!(base_asset.total_supply, expected_base_supply.to_string());

    let owner_nonce_after = client
        .get_token_nonce_call(None, GetTokenNonceRequest { owner_id: owner_id_hex.clone(), asset_id: None, at_block_hash: None })
        .await
        .unwrap();
    assert_eq!(owner_nonce_after.expected_next_nonce, owner_nonce);
    let base_asset_nonce_after = client
        .get_token_nonce_call(
            None,
            GetTokenNonceRequest { owner_id: owner_id_hex.clone(), asset_id: Some(base_asset_id.clone()), at_block_hash: None },
        )
        .await
        .unwrap();
    assert_eq!(base_asset_nonce_after.expected_next_nonce, base_asset_nonce);
    let liquidity_asset_nonce_after = client
        .get_token_nonce_call(
            None,
            GetTokenNonceRequest { owner_id: owner_id_hex.clone(), asset_id: Some(liquidity_asset_id.clone()), at_block_hash: None },
        )
        .await
        .unwrap();
    assert_eq!(liquidity_asset_nonce_after.expected_next_nonce, liquidity_asset_nonce);

    for wallet in &stress_wallets {
        let wallet_nonce_after = client
            .get_token_nonce_call(
                None,
                GetTokenNonceRequest { owner_id: wallet.owner_id_hex.clone(), asset_id: None, at_block_hash: None },
            )
            .await
            .unwrap();
        assert_eq!(
            wallet_nonce_after.expected_next_nonce, wallet.owner_nonce,
            "wrong owner nonce for multi-wallet stress owner {}",
            wallet.label
        );
    }

    for (asset_id, name, symbol, asset_owner_id_hex, initial_mint) in &created_assets {
        let asset = client
            .get_token_asset_call(None, GetTokenAssetRequest { asset_id: asset_id.clone(), at_block_hash: None })
            .await
            .unwrap()
            .asset
            .unwrap_or_else(|| panic!("stress-created asset {asset_id} is missing"));
        assert_eq!(asset.name.as_str(), name.as_str());
        assert_eq!(asset.symbol.as_str(), symbol.as_str());
        assert_eq!(asset.total_supply, initial_mint.to_string());
        let balance = client
            .get_token_balance_call(
                None,
                GetTokenBalanceRequest { asset_id: asset_id.clone(), owner_id: asset_owner_id_hex.clone(), at_block_hash: None },
            )
            .await
            .unwrap();
        assert_eq!(balance.balance, initial_mint.to_string(), "wrong owner balance for stress-created asset {asset_id}");
    }

    let assets = client
        .get_token_assets_call(None, GetTokenAssetsRequest { offset: 0, limit: 100, query: None, at_block_hash: None })
        .await
        .unwrap();
    assert!(
        assets.total >= created_assets.len() as u64 + 2,
        "expected all stress-created assets plus setup assets, got total={} created={}",
        assets.total,
        created_assets.len()
    );

    let holders = client
        .get_token_holders_call(
            None,
            GetTokenHoldersRequest { asset_id: base_asset_id.clone(), offset: 0, limit: 100, at_block_hash: None },
        )
        .await
        .unwrap();
    assert!(holders
        .holders
        .iter()
        .any(|entry| entry.owner_id == owner_id_hex && entry.balance == expected_owner_base_balance.to_string()));
    assert!(holders
        .holders
        .iter()
        .any(|entry| entry.owner_id == receiver_id_hex && entry.balance == expected_receiver_base_balance.to_string()));
    for wallet in &stress_wallets {
        let wallet_balance = client
            .get_token_balance_call(
                None,
                GetTokenBalanceRequest { asset_id: base_asset_id.clone(), owner_id: wallet.owner_id_hex.clone(), at_block_hash: None },
            )
            .await
            .unwrap();
        assert_eq!(
            wallet_balance.balance,
            wallet.expected_base_balance.to_string(),
            "wrong base asset balance for multi-wallet stress owner {}",
            wallet.label
        );
        assert!(holders
            .holders
            .iter()
            .any(|entry| { entry.owner_id == wallet.owner_id_hex && entry.balance == wallet.expected_base_balance.to_string() }));
    }

    let owner_balances = client
        .get_token_balances_by_owner_call(
            None,
            GetTokenBalancesByOwnerRequest {
                owner_id: owner_id_hex.clone(),
                offset: 0,
                limit: (created_assets.len() + 16).min(u32::MAX as usize) as u32,
                include_assets: true,
                at_block_hash: None,
            },
        )
        .await
        .unwrap();
    assert!(owner_balances
        .balances
        .iter()
        .any(|entry| entry.asset_id == base_asset_id && entry.balance == expected_owner_base_balance.to_string()));
    assert!(created_assets.iter().filter(|(_, _, _, asset_owner_id_hex, _)| asset_owner_id_hex == &owner_id_hex).all(
        |(asset_id, _, _, _, initial_mint)| {
            owner_balances
                .balances
                .iter()
                .any(|entry| entry.asset_id.as_str() == asset_id.as_str() && entry.balance == initial_mint.to_string())
        }
    ));
    for wallet in &stress_wallets {
        let wallet_balances = client
            .get_token_balances_by_owner_call(
                None,
                GetTokenBalancesByOwnerRequest {
                    owner_id: wallet.owner_id_hex.clone(),
                    offset: 0,
                    limit: (wallet.owner_nonce as usize + 16).min(u32::MAX as usize) as u32,
                    include_assets: true,
                    at_block_hash: None,
                },
            )
            .await
            .unwrap();
        assert!(wallet_balances
            .balances
            .iter()
            .any(|entry| { entry.asset_id == base_asset_id && entry.balance == wallet.expected_base_balance.to_string() }));
    }

    let pool_after = client
        .get_liquidity_pool_state_call(
            None,
            GetLiquidityPoolStateRequest { asset_id: liquidity_asset_id.clone(), at_block_hash: None },
        )
        .await
        .unwrap()
        .pool
        .expect("liquidity pool must exist after long stress");
    assert_eq!(pool_after.pool_nonce, expected_pool_nonce);
    let liquidity_asset = client
        .get_token_asset_call(None, GetTokenAssetRequest { asset_id: liquidity_asset_id.clone(), at_block_hash: None })
        .await
        .unwrap()
        .asset
        .expect("liquidity asset must exist after long stress");
    assert_eq!(liquidity_asset.total_supply, pool_after.total_supply);
    let liquidity_total_supply = pool_after.total_supply.parse::<u128>().unwrap();
    let liquidity_real_token_reserves = pool_after.real_token_reserves.parse::<u128>().unwrap();
    let liquidity_max_supply = pool_after.max_supply.parse::<u128>().unwrap();
    assert_eq!(liquidity_total_supply + liquidity_real_token_reserves, liquidity_max_supply);
    assert!(pool_after.real_cpay_reserves_sompi.parse::<u64>().unwrap() >= MIN_LIQUIDITY_SEED_RESERVE_SOMPI);
    assert!(pool_after.vault_value_sompi.parse::<u64>().unwrap() >= MIN_LIQUIDITY_SEED_RESERVE_SOMPI);

    let liquidity_owner_balance = client
        .get_token_balance_call(
            None,
            GetTokenBalanceRequest { asset_id: liquidity_asset_id.clone(), owner_id: owner_id_hex.clone(), at_block_hash: None },
        )
        .await
        .unwrap();
    assert!(liquidity_owner_balance.balance.parse::<u128>().unwrap() > 0);
    let liquidity_holders = client
        .get_liquidity_holders_call(
            None,
            GetLiquidityHoldersRequest { asset_id: liquidity_asset_id.clone(), offset: 0, limit: 100, at_block_hash: None },
        )
        .await
        .unwrap();
    assert!(liquidity_holders.total >= 1);

    let mut event_txids = HashSet::new();
    let mut fetched_events = 0usize;
    let mut after_sequence = 0u64;
    let mut event_pages = 0usize;
    let max_event_pages = (token_txids.len() / TOKEN_EVENTS_RPC_PAGE_LIMIT as usize) + 16;
    loop {
        let events = client
            .get_token_events_call(
                None,
                GetTokenEventsRequest { after_sequence, limit: TOKEN_EVENTS_RPC_PAGE_LIMIT, at_block_hash: None },
            )
            .await
            .unwrap();
        if events.events.is_empty() {
            break;
        }

        event_pages += 1;
        fetched_events += events.events.len();
        let last_sequence = events.events.last().unwrap().sequence;
        assert!(
            last_sequence > after_sequence,
            "Atomic event pagination did not advance: after_sequence={after_sequence} last_sequence={last_sequence}"
        );
        for event in &events.events {
            event_txids.insert(event.txid);
        }
        after_sequence = last_sequence;

        if events.events.len() < TOKEN_EVENTS_RPC_PAGE_LIMIT as usize {
            break;
        }
        assert!(
            event_pages <= max_event_pages,
            "Atomic event pagination exceeded expected pages: pages={event_pages} fetched_events={fetched_events} txids={}",
            token_txids.len()
        );
    }

    let missing_event_txids = token_txids
        .iter()
        .filter(|(_, txid)| !event_txids.contains(txid))
        .take(12)
        .map(|(label, txid)| format!("{label}:{txid}"))
        .collect::<Vec<_>>();
    assert!(
        missing_event_txids.is_empty(),
        "missing Atomic events for stress txids: missing_sample=[{}] fetched_events={fetched_events} event_pages={event_pages} expected_txids={}",
        missing_event_txids.join(", "),
        token_txids.len()
    );

    let state_hash_before = client.get_token_state_hash_call(None, GetTokenStateHashRequest { at_block_hash: None }).await.unwrap();
    assert_consensus_atomic_hash_exists(&client, state_hash_before.context.at_block_hash, "long stress final context").await;
    let snapshot_dir = tempfile::tempdir().unwrap();
    let snapshot_path: PathBuf = snapshot_dir.path().join("atomic-long-full-chain-stress.snapshot");
    client
        .export_token_snapshot_call(None, ExportTokenSnapshotRequest { path: snapshot_path.to_string_lossy().to_string() })
        .await
        .unwrap();
    client
        .import_token_snapshot_call(None, ImportTokenSnapshotRequest { path: snapshot_path.to_string_lossy().to_string() })
        .await
        .unwrap();
    let state_hash_after = client.get_token_state_hash_call(None, GetTokenStateHashRequest { at_block_hash: None }).await.unwrap();
    assert_eq!(state_hash_after.context.state_hash, state_hash_before.context.state_hash);

    let sink = client.get_block_dag_info().await.unwrap().sink;
    let health = wait_for_healthy_atomic_at_sink(&client, sink, "long full-chain stress final sink").await;
    assert_eq!(health.token_state, "healthy");
    assert!(!health.is_degraded);
    assert!(!health.bootstrap_in_progress);
    assert!(health.live_correct);
    assert_eq!(health.state_hash, state_hash_before.context.state_hash);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn atomic_token_atomic_enabled_reorg_emits_reorged_event() {
    cryptix_core::log::try_init_logger("INFO");
    let mut daemon1 = Daemon::new_random_with_args(atomic_args(), 10);
    let mut daemon2 = Daemon::new_random_with_args(atomic_args(), 10);
    let client1 = daemon1.start().await;
    let client2 = daemon2.start().await;

    let (owner_sk, owner_pk) = secp256k1::generate_keypair(&mut thread_rng());
    let owner_address = Address::new(daemon1.network.into(), Version::PubKey, &owner_pk.x_only_public_key().0.serialize());
    let owner_id = owner_id_from_address(&owner_address);
    let coinbase_maturity = daemon1.args.read().coinbase_maturity_override.unwrap_or(SIMNET_PARAMS.coinbase_maturity);

    let utxos = mine_until_spendable_utxos(&client1, &owner_address, coinbase_maturity, 1).await;

    let create_tx = build_payload_tx(
        Keypair::from_secret_key(secp256k1::SECP256K1, &owner_sk),
        &utxos[0],
        &owner_address,
        payload_create_asset(0, 1, 8, owner_id, b"R", b"R", b""),
    );
    submit_and_wait_indexed(&client1, &create_tx, &owner_address).await;

    let status =
        client1.get_token_op_status_call(None, GetTokenOpStatusRequest { txid: create_tx.id(), at_block_hash: None }).await.unwrap();
    assert_eq!(status.apply_status, Some(0));

    let tip1 = client1.get_block_dag_info().await.unwrap().block_count;
    let (_blank_sk, blank_pk) = secp256k1::generate_keypair(&mut thread_rng());
    let blank_addr = Address::new(daemon2.network.into(), Version::PubKey, &blank_pk.x_only_public_key().0.serialize());
    loop {
        let tip2 = client2.get_block_dag_info().await.unwrap().block_count;
        if tip2 >= tip1 + 40 {
            break;
        }
        mine_blocks(&client2, &blank_addr, 1).await;
    }

    let chain2 = client2.get_virtual_chain_from_block(cryptix_consensus::params::SIMNET_GENESIS.hash, true).await.unwrap();
    for hash in chain2.added_chain_block_hashes {
        let block = client2.get_block_call(None, GetBlockRequest { hash, include_transactions: true }).await.unwrap().block;
        let raw_block = RpcRawBlock { header: Header::from(&block.header).into(), transactions: block.transactions };
        let _ = client1.submit_block(raw_block, false).await;
    }

    let txid = create_tx.id();
    let mut reorg_observed = false;
    for _ in 0..120 {
        let status_after =
            client1.get_token_op_status_call(None, GetTokenOpStatusRequest { txid, at_block_hash: None }).await.unwrap();
        let events = client1
            .get_token_events_call(None, GetTokenEventsRequest { after_sequence: 0, limit: 2000, at_block_hash: None })
            .await
            .unwrap();
        if status_after.apply_status.is_none() && events.events.iter().any(|event| event.txid == txid && event.event_type == 2) {
            reorg_observed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(reorg_observed, "expected reorged token event and removed op status");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn atomic_token_reorg_across_payload_hardfork_reverts_state_and_accepts_fresh_ops() {
    cryptix_core::log::try_init_logger("INFO");
    let mut daemon1 = Daemon::new_random_with_args(atomic_args(), 10);
    let mut daemon2 = Daemon::new_random_with_args(atomic_args(), 10);
    let client1 = daemon1.start().await;
    let client2 = daemon2.start().await;

    let startup_info = client1.get_server_info().await.unwrap();
    assert!(
        startup_info.virtual_daa_score < ATOMIC_TEST_PAYLOAD_HF_DAA,
        "test must start before payload HF: virtual_daa={} hf={}",
        startup_info.virtual_daa_score,
        ATOMIC_TEST_PAYLOAD_HF_DAA
    );

    let (losing_owner_sk, losing_owner_pk) = secp256k1::generate_keypair(&mut thread_rng());
    let losing_owner_address =
        Address::new(daemon1.network.into(), Version::PubKey, &losing_owner_pk.x_only_public_key().0.serialize());
    let losing_owner_id = owner_id_from_address(&losing_owner_address);
    let losing_owner_id_hex = hex32(losing_owner_id);

    let (_receiver_sk, receiver_pk) = secp256k1::generate_keypair(&mut thread_rng());
    let receiver_address = Address::new(daemon1.network.into(), Version::PubKey, &receiver_pk.x_only_public_key().0.serialize());
    let receiver_id = owner_id_from_address(&receiver_address);
    let receiver_id_hex = hex32(receiver_id);

    let (winning_owner_sk, winning_owner_pk) = secp256k1::generate_keypair(&mut thread_rng());
    let winning_owner_address =
        Address::new(daemon1.network.into(), Version::PubKey, &winning_owner_pk.x_only_public_key().0.serialize());
    let winning_owner_id = owner_id_from_address(&winning_owner_address);
    let winning_owner_id_hex = hex32(winning_owner_id);

    let coinbase_maturity = daemon1.args.read().coinbase_maturity_override.unwrap_or(SIMNET_PARAMS.coinbase_maturity);
    let mut losing_utxos = mine_until_spendable_utxos(&client1, &losing_owner_address, coinbase_maturity, 4).await;
    losing_utxos.truncate(4);

    let post_hf_info = client1.get_server_info().await.unwrap();
    assert!(
        post_hf_info.virtual_daa_score >= ATOMIC_TEST_PAYLOAD_HF_DAA,
        "mining spendable UTXOs must cross payload HF: virtual_daa={} hf={}",
        post_hf_info.virtual_daa_score,
        ATOMIC_TEST_PAYLOAD_HF_DAA
    );
    let pre_ops_health =
        wait_for_healthy_atomic_at_sink(&client1, client1.get_block_dag_info().await.unwrap().sink, "pre-reorg setup").await;
    assert_eq!(pre_ops_health.token_state, "healthy");

    let pre_ops_state = client1.get_token_state_hash_call(None, GetTokenStateHashRequest { at_block_hash: None }).await.unwrap();
    assert_consensus_atomic_hash_exists(&client1, pre_ops_state.context.at_block_hash, "pre-reorg token context").await;

    let create_tx = build_payload_tx(
        Keypair::from_secret_key(secp256k1::SECP256K1, &losing_owner_sk),
        &losing_utxos[0],
        &losing_owner_address,
        payload_create_asset(0, 1, 8, losing_owner_id, b"ReorgSuite", b"RGS", b"losing-branch"),
    );
    submit_and_wait_indexed(&client1, &create_tx, &losing_owner_address).await;
    let asset_id = create_tx.id().to_string();
    let asset_id_bytes = create_tx.id().as_bytes();

    let mint_tx = build_payload_tx(
        Keypair::from_secret_key(secp256k1::SECP256K1, &losing_owner_sk),
        &losing_utxos[1],
        &losing_owner_address,
        payload_mint(0, 1, asset_id_bytes, losing_owner_id, 1_000),
    );
    submit_and_wait_indexed(&client1, &mint_tx, &losing_owner_address).await;

    let transfer_tx = build_payload_tx(
        Keypair::from_secret_key(secp256k1::SECP256K1, &losing_owner_sk),
        &losing_utxos[2],
        &losing_owner_address,
        payload_transfer(0, 2, asset_id_bytes, receiver_id, 300),
    );
    submit_and_wait_indexed(&client1, &transfer_tx, &losing_owner_address).await;

    let burn_tx = build_payload_tx(
        Keypair::from_secret_key(secp256k1::SECP256K1, &losing_owner_sk),
        &losing_utxos[3],
        &losing_owner_address,
        payload_burn(0, 3, asset_id_bytes, 200),
    );
    submit_and_wait_indexed(&client1, &burn_tx, &losing_owner_address).await;

    let losing_txids = vec![create_tx.id(), mint_tx.id(), transfer_tx.id(), burn_tx.id()];
    let events_before = client1
        .get_token_events_call(None, GetTokenEventsRequest { after_sequence: 0, limit: 1000, at_block_hash: None })
        .await
        .unwrap();
    let mut applied_event_ids = Vec::with_capacity(losing_txids.len());
    for txid in &losing_txids {
        let status =
            client1.get_token_op_status_call(None, GetTokenOpStatusRequest { txid: *txid, at_block_hash: None }).await.unwrap();
        assert_eq!(status.apply_status, Some(0), "losing branch tx {txid} must be applied before reorg");
        let event = events_before
            .events
            .iter()
            .find(|event| event.txid == *txid && event.apply_status == 0 && event.reorg_of_event_id.is_none())
            .unwrap_or_else(|| panic!("missing applied token event for losing branch tx {txid}"));
        applied_event_ids.push((*txid, event.event_id.clone()));
    }

    let owner_balance_before = client1
        .get_token_balance_call(
            None,
            GetTokenBalanceRequest { asset_id: asset_id.clone(), owner_id: losing_owner_id_hex.clone(), at_block_hash: None },
        )
        .await
        .unwrap();
    let receiver_balance_before = client1
        .get_token_balance_call(
            None,
            GetTokenBalanceRequest { asset_id: asset_id.clone(), owner_id: receiver_id_hex.clone(), at_block_hash: None },
        )
        .await
        .unwrap();
    assert_eq!(owner_balance_before.balance, "500");
    assert_eq!(receiver_balance_before.balance, "300");

    let asset_before = client1
        .get_token_asset_call(None, GetTokenAssetRequest { asset_id: asset_id.clone(), at_block_hash: None })
        .await
        .unwrap()
        .asset
        .expect("losing branch asset must exist before reorg");
    assert_eq!(asset_before.total_supply, "800");

    let losing_owner_nonce_before = client1
        .get_token_nonce_call(
            None,
            GetTokenNonceRequest { owner_id: losing_owner_id_hex.clone(), asset_id: None, at_block_hash: None },
        )
        .await
        .unwrap();
    let losing_asset_nonce_before = client1
        .get_token_nonce_call(
            None,
            GetTokenNonceRequest { owner_id: losing_owner_id_hex.clone(), asset_id: Some(asset_id.clone()), at_block_hash: None },
        )
        .await
        .unwrap();
    assert_eq!(losing_owner_nonce_before.expected_next_nonce, 2);
    assert_eq!(losing_asset_nonce_before.expected_next_nonce, 4);

    let state_before_reorg = client1.get_token_state_hash_call(None, GetTokenStateHashRequest { at_block_hash: None }).await.unwrap();
    assert_ne!(state_before_reorg.context.state_hash, pre_ops_state.context.state_hash);
    assert_consensus_atomic_hash_exists(&client1, state_before_reorg.context.at_block_hash, "losing branch token context").await;

    let tip1_count = client1.get_block_dag_info().await.unwrap().block_count;
    while client2.get_block_dag_info().await.unwrap().block_count < tip1_count + 40 {
        mine_blocks(&client2, &winning_owner_address, 1).await;
    }

    let chain2 = client2.get_virtual_chain_from_block(cryptix_consensus::params::SIMNET_GENESIS.hash, true).await.unwrap();
    assert!(chain2.removed_chain_block_hashes.is_empty());
    let winning_blocks = chain2.added_chain_block_hashes;
    let winning_sink = *winning_blocks.last().expect("winning chain must contain selected blocks");
    for hash in winning_blocks {
        let block = client2.get_block_call(None, GetBlockRequest { hash, include_transactions: true }).await.unwrap().block;
        let raw_block = RpcRawBlock { header: Header::from(&block.header).into(), transactions: block.transactions };
        let _ = client1.submit_block(raw_block, false).await;
    }

    let sink_client = client1.clone();
    wait_for(
        100,
        300,
        move || {
            async fn adopted(client: GrpcClient, expected_sink: cryptix_hashes::Hash) -> bool {
                client.get_block_dag_info().await.map(|info| info.sink == expected_sink).unwrap_or(false)
            }
            Box::pin(adopted(sink_client.clone(), winning_sink))
        },
        "node did not adopt imported winning branch",
    )
    .await;

    let health_after_reorg = wait_for_healthy_atomic_at_sink(&client1, winning_sink, "post-reorg winning branch").await;
    assert_eq!(health_after_reorg.last_applied_block, Some(winning_sink));
    assert_consensus_atomic_hash_exists(&client1, winning_sink, "winning sink after reorg").await;

    let state_after_reorg = client1.get_token_state_hash_call(None, GetTokenStateHashRequest { at_block_hash: None }).await.unwrap();
    assert_eq!(state_after_reorg.context.at_block_hash, winning_sink);
    assert_eq!(health_after_reorg.state_hash, state_after_reorg.context.state_hash);
    assert_eq!(
        state_after_reorg.context.state_hash, pre_ops_state.context.state_hash,
        "reorg to a token-empty winning branch must restore the exact pre-token-op Atomic state"
    );
    assert_ne!(state_after_reorg.context.state_hash, state_before_reorg.context.state_hash);

    let events_after = client1
        .get_token_events_call(None, GetTokenEventsRequest { after_sequence: 0, limit: 2000, at_block_hash: None })
        .await
        .unwrap();
    for (txid, applied_event_id) in &applied_event_ids {
        let status =
            client1.get_token_op_status_call(None, GetTokenOpStatusRequest { txid: *txid, at_block_hash: None }).await.unwrap();
        assert!(status.apply_status.is_none(), "reorged tx {txid} must not keep an op status");
        assert!(
            events_after.events.iter().any(|event| {
                event.txid == *txid && event.event_type == 2 && event.reorg_of_event_id.as_deref() == Some(applied_event_id.as_str())
            }),
            "missing reorged event for tx {txid} that points back to applied event {applied_event_id}"
        );
    }

    let asset_after =
        client1.get_token_asset_call(None, GetTokenAssetRequest { asset_id: asset_id.clone(), at_block_hash: None }).await.unwrap();
    assert!(asset_after.asset.is_none(), "losing branch asset must disappear after reorg");
    let owner_balance_after = client1
        .get_token_balance_call(
            None,
            GetTokenBalanceRequest { asset_id: asset_id.clone(), owner_id: losing_owner_id_hex.clone(), at_block_hash: None },
        )
        .await
        .unwrap();
    let receiver_balance_after = client1
        .get_token_balance_call(
            None,
            GetTokenBalanceRequest { asset_id: asset_id.clone(), owner_id: receiver_id_hex.clone(), at_block_hash: None },
        )
        .await
        .unwrap();
    assert_eq!(owner_balance_after.balance, "0");
    assert_eq!(receiver_balance_after.balance, "0");

    let losing_owner_nonce_after = client1
        .get_token_nonce_call(
            None,
            GetTokenNonceRequest { owner_id: losing_owner_id_hex.clone(), asset_id: None, at_block_hash: None },
        )
        .await
        .unwrap();
    let losing_asset_nonce_after = client1
        .get_token_nonce_call(
            None,
            GetTokenNonceRequest { owner_id: losing_owner_id_hex.clone(), asset_id: Some(asset_id.clone()), at_block_hash: None },
        )
        .await
        .unwrap();
    assert_eq!(losing_owner_nonce_after.expected_next_nonce, 1);
    assert_eq!(losing_asset_nonce_after.expected_next_nonce, 1);

    let assets_after = client1
        .get_token_assets_call(
            None,
            GetTokenAssetsRequest { offset: 0, limit: 100, query: Some("RGS".to_string()), at_block_hash: None },
        )
        .await
        .unwrap();
    assert!(!assets_after.assets.iter().any(|asset| asset.asset_id == asset_id));

    let winner_nonce_after_reorg = client1
        .get_token_nonce_call(
            None,
            GetTokenNonceRequest { owner_id: winning_owner_id_hex.clone(), asset_id: None, at_block_hash: None },
        )
        .await
        .unwrap();
    assert_eq!(winner_nonce_after_reorg.expected_next_nonce, 1);
    let winner_utxos = fetch_spendable_utxos(&client1, winning_owner_address.clone(), coinbase_maturity).await;
    assert!(!winner_utxos.is_empty(), "winning branch must fund the post-reorg owner");

    let fresh_create_tx = build_payload_tx(
        Keypair::from_secret_key(secp256k1::SECP256K1, &winning_owner_sk),
        &winner_utxos[0],
        &winning_owner_address,
        payload_create_asset(0, 1, 0, winning_owner_id, b"AfterReorg", b"AFT", b"winning-branch"),
    );
    let fresh_asset_id = fresh_create_tx.id().to_string();
    submit_and_wait_indexed(&client1, &fresh_create_tx, &winning_owner_address).await;
    let fresh_status = client1
        .get_token_op_status_call(None, GetTokenOpStatusRequest { txid: fresh_create_tx.id(), at_block_hash: None })
        .await
        .unwrap();
    assert_eq!(fresh_status.apply_status, Some(0));
    let fresh_asset = client1
        .get_token_asset_call(None, GetTokenAssetRequest { asset_id: fresh_asset_id, at_block_hash: None })
        .await
        .unwrap()
        .asset
        .expect("fresh post-reorg asset must exist");
    assert_eq!(fresh_asset.symbol, "AFT");

    let old_asset_after_fresh_op =
        client1.get_token_asset_call(None, GetTokenAssetRequest { asset_id, at_block_hash: None }).await.unwrap();
    assert!(old_asset_after_fresh_op.asset.is_none(), "fresh post-reorg op must not resurrect losing branch asset");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn atomic_token_reorg_applies_winning_branch_token_ops() {
    cryptix_core::log::try_init_logger("INFO");
    let mut daemon1 = Daemon::new_random_with_args(atomic_args(), 10);
    let mut daemon2 = Daemon::new_random_with_args(atomic_args(), 10);
    let client1 = daemon1.start().await;
    let client2 = daemon2.start().await;

    let (losing_owner_sk, losing_owner_pk) = secp256k1::generate_keypair(&mut thread_rng());
    let losing_owner_address =
        Address::new(daemon1.network.into(), Version::PubKey, &losing_owner_pk.x_only_public_key().0.serialize());
    let losing_owner_id = owner_id_from_address(&losing_owner_address);

    let (winning_owner_sk, winning_owner_pk) = secp256k1::generate_keypair(&mut thread_rng());
    let winning_owner_address =
        Address::new(daemon1.network.into(), Version::PubKey, &winning_owner_pk.x_only_public_key().0.serialize());
    let winning_owner_id = owner_id_from_address(&winning_owner_address);

    let coinbase_maturity = daemon1.args.read().coinbase_maturity_override.unwrap_or(SIMNET_PARAMS.coinbase_maturity);
    let losing_utxos = mine_until_spendable_utxos(&client1, &losing_owner_address, coinbase_maturity, 1).await;
    let pre_reorg_state = client1.get_token_state_hash_call(None, GetTokenStateHashRequest { at_block_hash: None }).await.unwrap();

    let losing_create_tx = build_payload_tx(
        Keypair::from_secret_key(secp256k1::SECP256K1, &losing_owner_sk),
        &losing_utxos[0],
        &losing_owner_address,
        payload_create_asset(0, 1, 0, losing_owner_id, b"LosingReorg", b"LRG", b"losing-branch"),
    );
    let losing_asset_id = losing_create_tx.id().to_string();
    submit_and_wait_indexed(&client1, &losing_create_tx, &losing_owner_address).await;
    let losing_status_before = client1
        .get_token_op_status_call(None, GetTokenOpStatusRequest { txid: losing_create_tx.id(), at_block_hash: None })
        .await
        .unwrap();
    assert_eq!(losing_status_before.apply_status, Some(0), "losing branch CAT tx must apply before reorg");

    let winning_utxos = mine_until_spendable_utxos(&client2, &winning_owner_address, coinbase_maturity, 1).await;
    let winning_create_tx = build_payload_tx(
        Keypair::from_secret_key(secp256k1::SECP256K1, &winning_owner_sk),
        &winning_utxos[0],
        &winning_owner_address,
        payload_create_asset(0, 1, 0, winning_owner_id, b"WinningReorg", b"WRG", b"winning-branch"),
    );
    let winning_asset_id = winning_create_tx.id().to_string();
    submit_and_wait_indexed(&client2, &winning_create_tx, &winning_owner_address).await;
    let winning_status_before = client2
        .get_token_op_status_call(None, GetTokenOpStatusRequest { txid: winning_create_tx.id(), at_block_hash: None })
        .await
        .unwrap();
    assert_eq!(winning_status_before.apply_status, Some(0), "winning branch CAT tx must apply before import");

    let client1_tip_count = client1.get_block_dag_info().await.unwrap().block_count;
    while client2.get_block_dag_info().await.unwrap().block_count < client1_tip_count + 40 {
        mine_blocks(&client2, &winning_owner_address, 1).await;
    }

    let chain2 = client2.get_virtual_chain_from_block(cryptix_consensus::params::SIMNET_GENESIS.hash, true).await.unwrap();
    assert!(chain2.removed_chain_block_hashes.is_empty());
    assert!(
        chain2
            .accepted_transaction_ids
            .iter()
            .any(|entry| entry.accepted_transaction_ids.iter().any(|txid| *txid == winning_create_tx.id())),
        "winning branch CAT tx must be in accepted_transaction_ids before import"
    );
    let winning_blocks = chain2.added_chain_block_hashes;
    let winning_sink = *winning_blocks.last().expect("winning branch must contain selected blocks");
    let client2_winning_state =
        client2.get_token_state_hash_call(None, GetTokenStateHashRequest { at_block_hash: None }).await.unwrap();
    assert_eq!(client2_winning_state.context.at_block_hash, winning_sink);

    for hash in winning_blocks {
        let block = client2.get_block_call(None, GetBlockRequest { hash, include_transactions: true }).await.unwrap().block;
        let raw_block = RpcRawBlock { header: Header::from(&block.header).into(), transactions: block.transactions };
        let _ = client1.submit_block(raw_block, false).await;
    }

    let sink_client = client1.clone();
    wait_for(
        100,
        300,
        move || {
            async fn adopted(client: GrpcClient, expected_sink: cryptix_hashes::Hash) -> bool {
                client.get_block_dag_info().await.map(|info| info.sink == expected_sink).unwrap_or(false)
            }
            Box::pin(adopted(sink_client.clone(), winning_sink))
        },
        "node did not adopt imported winning branch with token ops",
    )
    .await;

    let health_after_reorg = wait_for_healthy_atomic_at_sink(&client1, winning_sink, "winning branch token-op reorg").await;
    assert_eq!(health_after_reorg.last_applied_block, Some(winning_sink));

    let state_after_reorg = client1.get_token_state_hash_call(None, GetTokenStateHashRequest { at_block_hash: None }).await.unwrap();
    assert_eq!(state_after_reorg.context.at_block_hash, winning_sink);
    assert_eq!(state_after_reorg.context.state_hash, health_after_reorg.state_hash);
    assert_eq!(
        state_after_reorg.context.state_hash, client2_winning_state.context.state_hash,
        "reorged node must match the winner node token state hash"
    );
    assert_ne!(
        state_after_reorg.context.state_hash, pre_reorg_state.context.state_hash,
        "winning branch CAT op must change token state relative to the pre-op base"
    );

    let losing_status_after = client1
        .get_token_op_status_call(None, GetTokenOpStatusRequest { txid: losing_create_tx.id(), at_block_hash: None })
        .await
        .unwrap();
    assert!(losing_status_after.apply_status.is_none(), "losing CAT tx must be removed by reorg");
    let winning_status_after = client1
        .get_token_op_status_call(None, GetTokenOpStatusRequest { txid: winning_create_tx.id(), at_block_hash: None })
        .await
        .unwrap();
    assert_eq!(winning_status_after.apply_status, Some(0), "winning CAT tx must apply during reorg import");

    let losing_asset_after =
        client1.get_token_asset_call(None, GetTokenAssetRequest { asset_id: losing_asset_id, at_block_hash: None }).await.unwrap();
    assert!(losing_asset_after.asset.is_none(), "losing branch asset must disappear after reorg");
    let winning_asset_after =
        client1.get_token_asset_call(None, GetTokenAssetRequest { asset_id: winning_asset_id, at_block_hash: None }).await.unwrap();
    assert_eq!(winning_asset_after.asset.expect("winning branch asset must exist after reorg").symbol, "WRG");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn atomic_token_reorg_applies_same_asset_competing_winning_ops() {
    cryptix_core::log::try_init_logger("INFO");
    let mut daemon1 = Daemon::new_random_with_args(atomic_args(), 10);
    let mut daemon2 = Daemon::new_random_with_args(atomic_args(), 10);
    let client1 = daemon1.start().await;
    let client2 = daemon2.start().await;

    let (owner_sk, owner_pk) = secp256k1::generate_keypair(&mut thread_rng());
    let owner_address = Address::new(daemon1.network.into(), Version::PubKey, &owner_pk.x_only_public_key().0.serialize());
    let owner_id = owner_id_from_address(&owner_address);
    let owner_id_hex = hex32(owner_id);
    let owner_keypair = || Keypair::from_secret_key(secp256k1::SECP256K1, &owner_sk);

    let (_receiver_sk, receiver_pk) = secp256k1::generate_keypair(&mut thread_rng());
    let receiver_address = Address::new(daemon1.network.into(), Version::PubKey, &receiver_pk.x_only_public_key().0.serialize());
    let receiver_id = owner_id_from_address(&receiver_address);
    let receiver_id_hex = hex32(receiver_id);

    let coinbase_maturity = daemon1.args.read().coinbase_maturity_override.unwrap_or(SIMNET_PARAMS.coinbase_maturity);
    let mut utxos = mine_until_spendable_utxos(&client1, &owner_address, coinbase_maturity, 7).await;
    utxos.truncate(7);

    let create_tx = build_payload_tx(
        owner_keypair(),
        &utxos[0],
        &owner_address,
        payload_create_asset_with_mint(0, 1, 0, 1_000_000, owner_id, owner_id, 10_000, b"SameAssetReorg", b"SAR", b"common-base"),
    );
    let asset_id = create_tx.id().to_string();
    let asset_id_bytes = create_tx.id().as_bytes();
    submit_and_wait_indexed(&client1, &create_tx, &owner_address).await;
    let common_sink = client1.get_block_dag_info().await.unwrap().sink;
    let common_state = client1.get_token_state_hash_call(None, GetTokenStateHashRequest { at_block_hash: None }).await.unwrap();

    let (common_blocks, _) =
        import_selected_chain_blocks(&client1, &client2, cryptix_consensus::params::SIMNET_GENESIS.hash, "same-asset common prefix")
            .await;
    assert!(common_blocks.contains(&common_sink), "common prefix import must include the common sink");
    wait_for_sink(&client2, common_sink, "node2 did not adopt same-asset common prefix").await;
    let client2_common_health = wait_for_healthy_atomic_at_sink(&client2, common_sink, "same-asset common prefix").await;
    assert_eq!(client2_common_health.state_hash, common_state.context.state_hash);

    let losing_mint_tx =
        build_payload_tx(owner_keypair(), &utxos[1], &owner_address, payload_mint(0, 1, asset_id_bytes, owner_id, 500));
    submit_and_wait_indexed(&client1, &losing_mint_tx, &owner_address).await;
    let losing_transfer_tx =
        build_payload_tx(owner_keypair(), &utxos[2], &owner_address, payload_transfer(0, 2, asset_id_bytes, receiver_id, 300));
    submit_and_wait_indexed(&client1, &losing_transfer_tx, &owner_address).await;
    let losing_burn_tx = build_payload_tx(owner_keypair(), &utxos[3], &owner_address, payload_burn(0, 3, asset_id_bytes, 100));
    submit_and_wait_indexed(&client1, &losing_burn_tx, &owner_address).await;
    let losing_txids = vec![
        ("losing-mint".to_string(), losing_mint_tx.id()),
        ("losing-transfer".to_string(), losing_transfer_tx.id()),
        ("losing-burn".to_string(), losing_burn_tx.id()),
    ];
    assert_token_statuses_applied(&client1, &losing_txids, "same-asset losing branch").await;
    let losing_state_before_reorg =
        client1.get_token_state_hash_call(None, GetTokenStateHashRequest { at_block_hash: None }).await.unwrap();
    assert_ne!(losing_state_before_reorg.context.state_hash, common_state.context.state_hash);

    let winning_mint_tx =
        build_payload_tx(owner_keypair(), &utxos[4], &owner_address, payload_mint(0, 1, asset_id_bytes, owner_id, 700));
    submit_and_wait_indexed(&client2, &winning_mint_tx, &owner_address).await;
    let winning_transfer_tx =
        build_payload_tx(owner_keypair(), &utxos[5], &owner_address, payload_transfer(0, 2, asset_id_bytes, receiver_id, 250));
    submit_and_wait_indexed(&client2, &winning_transfer_tx, &owner_address).await;
    let winning_burn_tx = build_payload_tx(owner_keypair(), &utxos[6], &owner_address, payload_burn(0, 3, asset_id_bytes, 50));
    submit_and_wait_indexed(&client2, &winning_burn_tx, &owner_address).await;
    let winning_txids = vec![
        ("winning-mint".to_string(), winning_mint_tx.id()),
        ("winning-transfer".to_string(), winning_transfer_tx.id()),
        ("winning-burn".to_string(), winning_burn_tx.id()),
    ];
    assert_token_statuses_applied(&client2, &winning_txids, "same-asset winning branch before import").await;

    let client1_tip_count = client1.get_block_dag_info().await.unwrap().block_count;
    while client2.get_block_dag_info().await.unwrap().block_count < client1_tip_count + 40 {
        mine_blocks(&client2, &owner_address, 1).await;
    }
    let client2_winning_sink = client2.get_block_dag_info().await.unwrap().sink;
    let client2_winning_health = wait_for_healthy_atomic_at_sink(&client2, client2_winning_sink, "same-asset winning branch").await;
    let client2_winning_state =
        client2.get_token_state_hash_call(None, GetTokenStateHashRequest { at_block_hash: None }).await.unwrap();
    assert_eq!(client2_winning_health.state_hash, client2_winning_state.context.state_hash);
    let client2_winning_cpay_snapshot = spendable_cpay_snapshot(&client2, &owner_address, coinbase_maturity).await;

    let (winning_blocks, winning_accepted) =
        import_selected_chain_blocks(&client2, &client1, common_sink, "same-asset winning branch").await;
    assert_eq!(*winning_blocks.last().expect("winning branch must have a sink"), client2_winning_sink);
    for (label, txid) in &winning_txids {
        assert!(winning_accepted.contains(txid), "same-asset winning branch did not accept {label}/{txid}");
    }

    wait_for_sink(&client1, client2_winning_sink, "node1 did not adopt same-asset winning branch").await;
    let health_after_reorg = wait_for_healthy_atomic_at_sink(&client1, client2_winning_sink, "same-asset post-reorg").await;
    let state_after_reorg = client1.get_token_state_hash_call(None, GetTokenStateHashRequest { at_block_hash: None }).await.unwrap();
    assert_eq!(state_after_reorg.context.at_block_hash, client2_winning_sink);
    assert_eq!(state_after_reorg.context.state_hash, health_after_reorg.state_hash);
    assert_eq!(
        state_after_reorg.context.state_hash, client2_winning_state.context.state_hash,
        "same-asset reorged node must match the winner node Atomic state hash"
    );
    assert_ne!(state_after_reorg.context.state_hash, losing_state_before_reorg.context.state_hash);
    assert_ne!(state_after_reorg.context.state_hash, common_state.context.state_hash);

    for (label, txid) in &losing_txids {
        let status =
            client1.get_token_op_status_call(None, GetTokenOpStatusRequest { txid: *txid, at_block_hash: None }).await.unwrap();
        assert!(status.apply_status.is_none(), "same-asset losing tx {label}/{txid} must be removed by reorg");
    }
    assert_token_statuses_applied(&client1, &winning_txids, "same-asset winning branch after reorg").await;

    let asset_after = client1
        .get_token_asset_call(None, GetTokenAssetRequest { asset_id: asset_id.clone(), at_block_hash: None })
        .await
        .unwrap()
        .asset
        .expect("same-asset token must survive on winning branch");
    assert_eq!(asset_after.total_supply, "10650");
    let owner_balance = client1
        .get_token_balance_call(
            None,
            GetTokenBalanceRequest { asset_id: asset_id.clone(), owner_id: owner_id_hex.clone(), at_block_hash: None },
        )
        .await
        .unwrap();
    let receiver_balance = client1
        .get_token_balance_call(
            None,
            GetTokenBalanceRequest { asset_id: asset_id.clone(), owner_id: receiver_id_hex.clone(), at_block_hash: None },
        )
        .await
        .unwrap();
    assert_eq!(owner_balance.balance, "10400");
    assert_eq!(receiver_balance.balance, "250");
    let cpay_snapshot_after_reorg = spendable_cpay_snapshot(&client1, &owner_address, coinbase_maturity).await;
    assert_eq!(
        cpay_snapshot_after_reorg, client2_winning_cpay_snapshot,
        "same-asset reorged node CPAY wallet UTXO set must match the winner node"
    );

    let owner_nonce = client1
        .get_token_nonce_call(None, GetTokenNonceRequest { owner_id: owner_id_hex.clone(), asset_id: None, at_block_hash: None })
        .await
        .unwrap();
    let asset_nonce = client1
        .get_token_nonce_call(None, GetTokenNonceRequest { owner_id: owner_id_hex, asset_id: Some(asset_id), at_block_hash: None })
        .await
        .unwrap();
    assert_eq!(owner_nonce.expected_next_nonce, 2);
    assert_eq!(asset_nonce.expected_next_nonce, 4);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn atomic_token_reorg_applies_same_pool_competing_liquidity_ops() {
    cryptix_core::log::try_init_logger("INFO");
    let mut daemon1 = Daemon::new_random_with_args(atomic_args(), 10);
    let mut daemon2 = Daemon::new_random_with_args(atomic_args(), 10);
    let client1 = daemon1.start().await;
    let client2 = daemon2.start().await;
    let consensus_manager = consensus_manager_from_daemon(&daemon1);

    let (owner_sk, owner_pk) = secp256k1::generate_keypair(&mut thread_rng());
    let owner_address = Address::new(daemon1.network.into(), Version::PubKey, &owner_pk.x_only_public_key().0.serialize());
    let owner_id = owner_id_from_address(&owner_address);
    let owner_id_hex = hex32(owner_id);

    let coinbase_maturity = daemon1.args.read().coinbase_maturity_override.unwrap_or(SIMNET_PARAMS.coinbase_maturity);
    let mut utxos = mine_until_spendable_utxos(&client1, &owner_address, coinbase_maturity, 3).await;
    utxos.truncate(3);

    let liquidity_fee = required_fee(1, 2);
    assert!(utxos[0].1.amount > MIN_LIQUIDITY_SEED_RESERVE_SOMPI + liquidity_fee);
    let liquidity_change = utxos[0].1.amount - MIN_LIQUIDITY_SEED_RESERVE_SOMPI - liquidity_fee;
    let create_liquidity_tx = build_payload_tx_with_outputs(
        &owner_sk,
        vec![(utxos[0].0, utxos[0].1.clone(), 1)],
        vec![
            TransactionOutput { value: MIN_LIQUIDITY_SEED_RESERVE_SOMPI, script_public_key: liquidity_vault_script() },
            TransactionOutput { value: liquidity_change, script_public_key: pay_to_address_script(&owner_address) },
        ],
        payload_create_liquidity_with_fee_recipient(
            0,
            1,
            LIQUIDITY_TOKEN_SUPPLY_RAW,
            100,
            &owner_address,
            0,
            0,
            b"SamePoolReorg",
            b"SPR",
        ),
    );
    let liquidity_asset_id = create_liquidity_tx.id().to_string();
    let liquidity_asset_bytes = create_liquidity_tx.id().as_bytes();
    submit_and_wait_indexed(&client1, &create_liquidity_tx, &owner_address).await;

    let common_pool = client1
        .get_liquidity_pool_state_call(
            None,
            GetLiquidityPoolStateRequest { asset_id: liquidity_asset_id.clone(), at_block_hash: None },
        )
        .await
        .unwrap()
        .pool
        .expect("common liquidity pool must exist before split");
    assert_eq!(common_pool.pool_nonce, 1);
    let common_sink = client1.get_block_dag_info().await.unwrap().sink;
    let common_state = client1.get_token_state_hash_call(None, GetTokenStateHashRequest { at_block_hash: None }).await.unwrap();

    let (common_blocks, _) =
        import_selected_chain_blocks(&client1, &client2, cryptix_consensus::params::SIMNET_GENESIS.hash, "same-pool common prefix")
            .await;
    assert!(common_blocks.contains(&common_sink), "common pool import must include the common sink");
    wait_for_sink(&client2, common_sink, "node2 did not adopt same-pool common prefix").await;
    let client2_common_health = wait_for_healthy_atomic_at_sink(&client2, common_sink, "same-pool common prefix").await;
    assert_eq!(client2_common_health.state_hash, common_state.context.state_hash);
    let client2_common_pool = client2
        .get_liquidity_pool_state_call(
            None,
            GetLiquidityPoolStateRequest { asset_id: liquidity_asset_id.clone(), at_block_hash: None },
        )
        .await
        .unwrap()
        .pool
        .expect("client2 common liquidity pool must exist before split");
    assert_eq!(client2_common_pool.vault_txid, common_pool.vault_txid);
    assert_eq!(client2_common_pool.vault_value_sompi, common_pool.vault_value_sompi);

    let losing_branch = apply_liquidity_buy_sell_claim_branch(
        &client1,
        &owner_sk,
        &owner_address,
        &liquidity_asset_id,
        liquidity_asset_bytes,
        &common_pool,
        &utxos[1],
        2_000_000_000,
        2,
        12_000_000,
        "same-pool-losing",
    )
    .await;
    let losing_pool_before_reorg = client1
        .get_liquidity_pool_state_call(
            None,
            GetLiquidityPoolStateRequest { asset_id: liquidity_asset_id.clone(), at_block_hash: None },
        )
        .await
        .unwrap()
        .pool
        .expect("losing pool must exist before reorg");
    let losing_state_before_reorg =
        client1.get_token_state_hash_call(None, GetTokenStateHashRequest { at_block_hash: None }).await.unwrap();
    assert_ne!(losing_state_before_reorg.context.state_hash, common_state.context.state_hash);

    let winning_branch = apply_liquidity_buy_sell_claim_branch(
        &client2,
        &owner_sk,
        &owner_address,
        &liquidity_asset_id,
        liquidity_asset_bytes,
        &client2_common_pool,
        &utxos[2],
        3_000_000_000,
        3,
        12_000_000,
        "same-pool-winning",
    )
    .await;

    let client1_tip_count = client1.get_block_dag_info().await.unwrap().block_count;
    while client2.get_block_dag_info().await.unwrap().block_count < client1_tip_count + 40 {
        mine_blocks(&client2, &owner_address, 1).await;
    }
    let client2_winning_sink = client2.get_block_dag_info().await.unwrap().sink;
    let client2_winning_health = wait_for_healthy_atomic_at_sink(&client2, client2_winning_sink, "same-pool winning branch").await;
    let client2_winning_state =
        client2.get_token_state_hash_call(None, GetTokenStateHashRequest { at_block_hash: None }).await.unwrap();
    assert_eq!(client2_winning_health.state_hash, client2_winning_state.context.state_hash);
    let client2_winning_pool = client2
        .get_liquidity_pool_state_call(
            None,
            GetLiquidityPoolStateRequest { asset_id: liquidity_asset_id.clone(), at_block_hash: None },
        )
        .await
        .unwrap()
        .pool
        .expect("winning pool must exist before import");
    let client2_winning_fee_state = client2
        .get_liquidity_fee_state_call(None, GetLiquidityFeeStateRequest { asset_id: liquidity_asset_id.clone(), at_block_hash: None })
        .await
        .unwrap();
    let client2_winning_holders = client2
        .get_liquidity_holders_call(
            None,
            GetLiquidityHoldersRequest { asset_id: liquidity_asset_id.clone(), offset: 0, limit: 100, at_block_hash: None },
        )
        .await
        .unwrap();
    let client2_winning_balance = client2
        .get_token_balance_call(
            None,
            GetTokenBalanceRequest { asset_id: liquidity_asset_id.clone(), owner_id: owner_id_hex.clone(), at_block_hash: None },
        )
        .await
        .unwrap();
    let client2_winning_quote = client2
        .get_liquidity_quote_call(
            None,
            GetLiquidityQuoteRequest {
                asset_id: liquidity_asset_id.clone(),
                side: 0,
                exact_in_amount: "1000000000".to_string(),
                at_block_hash: None,
            },
        )
        .await
        .unwrap();
    let client2_winning_cpay_snapshot = spendable_cpay_snapshot(&client2, &owner_address, coinbase_maturity).await;

    let (winning_blocks, winning_accepted) =
        import_selected_chain_blocks(&client2, &client1, common_sink, "same-pool winning branch").await;
    assert_eq!(*winning_blocks.last().expect("winning pool branch must have a sink"), client2_winning_sink);
    for (label, txid) in &winning_branch.txids {
        assert!(winning_accepted.contains(txid), "same-pool winning branch did not accept {label}/{txid}");
    }

    wait_for_sink(&client1, client2_winning_sink, "node1 did not adopt same-pool winning branch").await;
    let health_after_reorg = wait_for_healthy_atomic_at_sink(&client1, client2_winning_sink, "same-pool post-reorg").await;
    let state_after_reorg = client1.get_token_state_hash_call(None, GetTokenStateHashRequest { at_block_hash: None }).await.unwrap();
    assert_eq!(state_after_reorg.context.at_block_hash, client2_winning_sink);
    assert_eq!(state_after_reorg.context.state_hash, health_after_reorg.state_hash);
    assert_eq!(
        state_after_reorg.context.state_hash, client2_winning_state.context.state_hash,
        "same-pool reorged node must match the winner node Atomic state hash"
    );
    assert_ne!(state_after_reorg.context.state_hash, losing_state_before_reorg.context.state_hash);

    for (label, txid) in &losing_branch.txids {
        let status =
            client1.get_token_op_status_call(None, GetTokenOpStatusRequest { txid: *txid, at_block_hash: None }).await.unwrap();
        assert!(status.apply_status.is_none(), "same-pool losing tx {label}/{txid} must be removed by reorg");
    }
    assert_token_statuses_applied(&client1, &winning_branch.txids, "same-pool winning branch after reorg").await;

    let pool_after_reorg = client1
        .get_liquidity_pool_state_call(
            None,
            GetLiquidityPoolStateRequest { asset_id: liquidity_asset_id.clone(), at_block_hash: None },
        )
        .await
        .unwrap()
        .pool
        .expect("same-pool liquidity state must exist after reorg");
    assert_eq!(pool_after_reorg.pool_nonce, client2_winning_pool.pool_nonce);
    assert_eq!(pool_after_reorg.vault_txid, client2_winning_pool.vault_txid);
    assert_eq!(pool_after_reorg.vault_output_index, client2_winning_pool.vault_output_index);
    assert_eq!(pool_after_reorg.vault_value_sompi, client2_winning_pool.vault_value_sompi);
    assert_eq!(pool_after_reorg.real_cpay_reserves_sompi, client2_winning_pool.real_cpay_reserves_sompi);
    assert_eq!(pool_after_reorg.liquidity_cpay_sompi, client2_winning_pool.liquidity_cpay_sompi);
    assert_eq!(pool_after_reorg.unclaimed_fee_total_sompi, client2_winning_pool.unclaimed_fee_total_sompi);
    assert_eq!(pool_after_reorg.real_token_reserves, client2_winning_pool.real_token_reserves);
    assert_eq!(pool_after_reorg.circulating_token_supply, client2_winning_pool.circulating_token_supply);
    assert_eq!(pool_after_reorg.current_spot_price_sompi, client2_winning_pool.current_spot_price_sompi);
    assert_ne!(
        pool_after_reorg.vault_value_sompi, losing_pool_before_reorg.vault_value_sompi,
        "same-pool reorg must replace losing CPAY vault state"
    );

    let fee_state_after = client1
        .get_liquidity_fee_state_call(None, GetLiquidityFeeStateRequest { asset_id: liquidity_asset_id.clone(), at_block_hash: None })
        .await
        .unwrap();
    assert_eq!(fee_state_after.total_unclaimed_sompi, client2_winning_fee_state.total_unclaimed_sompi);
    assert_eq!(fee_state_after.recipients.len(), 1);
    assert_eq!(client2_winning_fee_state.recipients.len(), 1);
    assert_eq!(fee_state_after.recipients[0].owner_id, client2_winning_fee_state.recipients[0].owner_id);
    assert_eq!(fee_state_after.recipients[0].address, client2_winning_fee_state.recipients[0].address);
    assert_eq!(fee_state_after.recipients[0].unclaimed_sompi, client2_winning_fee_state.recipients[0].unclaimed_sompi);

    let holders_after = client1
        .get_liquidity_holders_call(
            None,
            GetLiquidityHoldersRequest { asset_id: liquidity_asset_id.clone(), offset: 0, limit: 100, at_block_hash: None },
        )
        .await
        .unwrap();
    let holder_after = holders_after
        .holders
        .iter()
        .find(|holder| holder.owner_id == owner_id_hex)
        .expect("owner must hold winning liquidity tokens after reorg");
    let holder_winning = client2_winning_holders
        .holders
        .iter()
        .find(|holder| holder.owner_id == owner_id_hex)
        .expect("winner node must report owner liquidity holder");
    assert_eq!(holder_after.balance, holder_winning.balance);

    let balance_after = client1
        .get_token_balance_call(
            None,
            GetTokenBalanceRequest { asset_id: liquidity_asset_id.clone(), owner_id: owner_id_hex.clone(), at_block_hash: None },
        )
        .await
        .unwrap();
    assert_eq!(balance_after.balance, client2_winning_balance.balance);

    let quote_after = client1
        .get_liquidity_quote_call(
            None,
            GetLiquidityQuoteRequest {
                asset_id: liquidity_asset_id,
                side: 0,
                exact_in_amount: "1000000000".to_string(),
                at_block_hash: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(quote_after.amount_out, client2_winning_quote.amount_out);
    assert_eq!(quote_after.fee_amount_sompi, client2_winning_quote.fee_amount_sompi);
    assert_eq!(quote_after.net_in_amount, client2_winning_quote.net_in_amount);
    let cpay_snapshot_after_reorg = spendable_cpay_snapshot(&client1, &owner_address, coinbase_maturity).await;
    assert_eq!(
        cpay_snapshot_after_reorg, client2_winning_cpay_snapshot,
        "same-pool reorged node CPAY wallet UTXO set must match the winner node"
    );

    let winning_claim_outpoint = TransactionOutpoint::new(winning_branch.claim_txid, 1);
    let winning_claim_utxo = virtual_utxo_entry_exact(consensus_manager.as_ref(), winning_claim_outpoint)
        .await
        .expect("winning fee-claim CPAY payout must exist after reorg");
    assert_eq!(winning_claim_utxo.amount, winning_branch.claim_amount_sompi);
    let losing_claim_outpoint = TransactionOutpoint::new(losing_branch.claim_txid, 1);
    assert!(
        virtual_utxo_entry_exact(consensus_manager.as_ref(), losing_claim_outpoint).await.is_none(),
        "losing fee-claim CPAY payout must disappear after reorg"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "long-running full-chain reorg stress test; run with --ignored and optionally CRYPTIX_REORG_STRESS_ROUNDS=16"]
async fn atomic_token_ignored_reorg_stress_mempool_blocks_and_state() {
    cryptix_core::log::try_init_logger("INFO");
    let rounds = reorg_stress_rounds_from_env();
    let mut daemon1 = Daemon::new_random_with_args(atomic_args(), 10);
    let mut daemon2 = Daemon::new_random_with_args(atomic_args(), 10);
    let client1 = daemon1.start().await;
    let client2 = daemon2.start().await;
    let consensus_manager = consensus_manager_from_daemon(&daemon1);

    let (owner_sk, owner_pk) = secp256k1::generate_keypair(&mut thread_rng());
    let owner_keypair = || Keypair::from_secret_key(secp256k1::SECP256K1, &owner_sk);
    let owner_pubkey_bytes = owner_pk.x_only_public_key().0.serialize();
    let owner_address = Address::new(daemon1.network.into(), Version::PubKey, &owner_pubkey_bytes);
    let owner_id = owner_id_from_address(&owner_address);
    let owner_id_hex = hex32(owner_id);

    let (_receiver_sk, receiver_pk) = secp256k1::generate_keypair(&mut thread_rng());
    let receiver_address = Address::new(daemon1.network.into(), Version::PubKey, &receiver_pk.x_only_public_key().0.serialize());
    let receiver_id = owner_id_from_address(&receiver_address);
    let receiver_id_hex = hex32(receiver_id);

    let (winning_owner_sk, winning_owner_pk) = secp256k1::generate_keypair(&mut thread_rng());
    let winning_owner_address =
        Address::new(daemon1.network.into(), Version::PubKey, &winning_owner_pk.x_only_public_key().0.serialize());
    let winning_owner_id = owner_id_from_address(&winning_owner_address);
    let winning_owner_id_hex = hex32(winning_owner_id);

    let mut stress_wallets = Vec::with_capacity(ATOMIC_REORG_STRESS_WALLET_COUNT);
    for wallet_index in 0..ATOMIC_REORG_STRESS_WALLET_COUNT {
        let (secret, public) = secp256k1::generate_keypair(&mut thread_rng());
        let pubkey_bytes = public.x_only_public_key().0.serialize();
        let address = Address::new(daemon1.network.into(), Version::PubKey, &pubkey_bytes);
        let owner_id = owner_id_from_address(&address);
        stress_wallets.push(StressWallet {
            label: format!("reorg-wallet-{wallet_index}"),
            secret,
            address,
            owner_id,
            owner_id_hex: hex32(owner_id),
            pubkey_bytes,
            queue: VecDeque::new(),
            consumed_outpoints: HashSet::new(),
            owner_nonce: 1,
            expected_base_balance: 0,
        });
    }

    let coinbase_maturity = daemon1.args.read().coinbase_maturity_override.unwrap_or(SIMNET_PARAMS.coinbase_maturity);
    let initial_utxos = mine_until_spendable_utxos(&client1, &owner_address, coinbase_maturity, 190).await;
    let mut utxo_queue: VecDeque<_> = initial_utxos.into();
    let mut consumed_outpoints = HashSet::new();
    let mut accepted_producer_txids = HashSet::new();
    for wallet in &mut stress_wallets {
        wallet.queue = mine_until_spendable_utxos(&client1, &wallet.address, coinbase_maturity, 18).await.into();
    }

    let pre_stress_sink = client1.get_block_dag_info().await.unwrap().sink;
    let pre_stress_health = wait_for_healthy_atomic_at_sink(&client1, pre_stress_sink, "reorg stress pre-token setup").await;
    assert_eq!(pre_stress_health.token_state, "healthy");
    let pre_stress_state = client1.get_token_state_hash_call(None, GetTokenStateHashRequest { at_block_hash: None }).await.unwrap();
    assert_eq!(pre_stress_state.context.at_block_hash, pre_stress_sink);
    assert_consensus_atomic_hash_exists(&client1, pre_stress_sink, "reorg stress pre-token state").await;

    let mut token_txids = Vec::<(String, TransactionId)>::new();
    let mut created_asset_ids = Vec::<String>::new();
    let mut active_stress_wallets = HashSet::new();
    let mut submitted_native = 0usize;
    let mut submitted_messenger = 0usize;
    let mut submitted_raw_payloads = 0usize;
    let mut submitted_token_creates = 0usize;
    let mut submitted_wallet_token_creates = 0usize;
    let mut submitted_base_ops = 0usize;
    let mut submitted_liquidity_buys = 0usize;
    let mut submitted_liquidity_sells = 0usize;
    let mut submitted_liquidity_claims = 0usize;
    let mut max_mempool_entries = 0usize;
    let mut max_block_template_txs = 0usize;
    let mut mined_stress_blocks = 0u64;

    let mut owner_nonce = 1u64;
    let base_create_utxo = pop_stress_utxo(&mut utxo_queue, &mut consumed_outpoints, "reorg stress base create");
    let base_create_tx = build_stress_payload_tx(
        owner_keypair(),
        &base_create_utxo,
        &owner_address,
        payload_create_asset_with_mint(
            0,
            owner_nonce,
            0,
            100_000_000,
            owner_id,
            owner_id,
            200_000,
            b"ReorgStressBase",
            b"RSB",
            b"reorg-stress-base",
        ),
    );
    owner_nonce += 1;
    let base_asset_id = base_create_tx.id().to_string();
    let base_asset_bytes = base_create_tx.id().as_bytes();
    token_txids.push(("reorg-setup-base-create".to_string(), base_create_tx.id()));
    created_asset_ids.push(base_asset_id.clone());
    submit_and_wait_indexed(&client1, &base_create_tx, &owner_address).await;
    accepted_producer_txids.insert(base_create_tx.id());

    let liquidity_utxo = pop_stress_utxo_with_min_amount(
        &mut utxo_queue,
        &mut consumed_outpoints,
        "reorg stress liquidity create",
        MIN_LIQUIDITY_SEED_RESERVE_SOMPI + required_fee(1, 2),
    );
    let liquidity_change = liquidity_utxo.1.amount - MIN_LIQUIDITY_SEED_RESERVE_SOMPI - required_fee(1, 2);
    let liquidity_create_tx = build_payload_tx_with_outputs(
        &owner_sk,
        vec![(liquidity_utxo.0, liquidity_utxo.1.clone(), 1)],
        vec![
            TransactionOutput { value: MIN_LIQUIDITY_SEED_RESERVE_SOMPI, script_public_key: liquidity_vault_script() },
            TransactionOutput { value: liquidity_change, script_public_key: pay_to_address_script(&owner_address) },
        ],
        payload_create_liquidity_with_fee_recipient(
            0,
            owner_nonce,
            LIQUIDITY_TOKEN_SUPPLY_RAW,
            100,
            &owner_address,
            0,
            0,
            b"ReorgStressPool",
            b"RSP",
        ),
    );
    owner_nonce += 1;
    let liquidity_asset_id = liquidity_create_tx.id().to_string();
    let liquidity_asset_bytes = liquidity_create_tx.id().as_bytes();
    token_txids.push(("reorg-setup-liquidity-create".to_string(), liquidity_create_tx.id()));
    created_asset_ids.push(liquidity_asset_id.clone());
    submit_and_wait_indexed(&client1, &liquidity_create_tx, &owner_address).await;
    accepted_producer_txids.insert(liquidity_create_tx.id());

    let mut base_asset_nonce = 1u64;
    let mut liquidity_asset_nonce = 1u64;
    let mut expected_pool_nonce = 1u64;
    let stress_addresses = stress_wallets.iter().map(|wallet| wallet.address.clone()).collect::<Vec<_>>();
    let stress_owner_ids = stress_wallets.iter().map(|wallet| wallet.owner_id).collect::<Vec<_>>();

    for round in 0..rounds {
        refill_stress_utxos(
            &client1,
            consensus_manager.as_ref(),
            &owner_address,
            coinbase_maturity,
            &mut utxo_queue,
            &consumed_outpoints,
            &accepted_producer_txids,
            90,
        )
        .await;
        for wallet in &mut stress_wallets {
            refill_stress_utxos(
                &client1,
                consensus_manager.as_ref(),
                &wallet.address,
                coinbase_maturity,
                &mut wallet.queue,
                &wallet.consumed_outpoints,
                &accepted_producer_txids,
                12,
            )
            .await;
        }

        let mut parallel_queued = Vec::new();
        let mut ordered_queued = Vec::new();
        let mut phase_token_txids = Vec::new();
        let mut phase_all_txids = Vec::new();

        for i in 0..10u64 {
            let utxo = pop_stress_utxo(&mut utxo_queue, &mut consumed_outpoints, "reorg stress native tx");
            let tx = build_stress_native_tx(owner_keypair(), &utxo, &owner_address);
            let label = format!("reorg-native-{round}-{i}");
            phase_all_txids.push(stress_tx_trace(label.clone(), tx.id(), vec![utxo], &accepted_producer_txids));
            parallel_queued.push((label, tx));
            submitted_native += 1;
        }

        for i in 0..10u64 {
            let utxo = pop_stress_utxo(&mut utxo_queue, &mut consumed_outpoints, "reorg stress messenger tx");
            let tx = build_stress_payload_tx(
                owner_keypair(),
                &utxo,
                &owner_address,
                messenger_payload_v1(700_000 + round * 10_000 + i, owner_pubkey_bytes, 160 + ((i % 5) as usize * 96)),
            );
            let label = format!("reorg-messenger-{round}-{i}");
            phase_all_txids.push(stress_tx_trace(label.clone(), tx.id(), vec![utxo], &accepted_producer_txids));
            parallel_queued.push((label, tx));
            submitted_messenger += 1;
        }

        for i in 0..6u64 {
            let utxo = pop_stress_utxo(&mut utxo_queue, &mut consumed_outpoints, "reorg stress raw payload tx");
            let mut payload = format!("RAW:reorg-stress:{round}:{i}:").into_bytes();
            payload.resize(280 + ((i % 4) as usize * 96), (round.wrapping_add(i) & 0xff) as u8);
            let tx = build_stress_payload_tx(owner_keypair(), &utxo, &owner_address, payload);
            let label = format!("reorg-raw-{round}-{i}");
            phase_all_txids.push(stress_tx_trace(label.clone(), tx.id(), vec![utxo], &accepted_producer_txids));
            parallel_queued.push((label, tx));
            submitted_raw_payloads += 1;
        }

        for wallet_index in 0..stress_wallets.len() {
            let recipient_index = (wallet_index + round as usize + 1) % stress_addresses.len();
            let wallet = &mut stress_wallets[wallet_index];
            let utxo = pop_stress_utxo(&mut wallet.queue, &mut wallet.consumed_outpoints, "reorg wallet native tx");
            let tx = build_stress_native_tx(wallet.keypair(), &utxo, &stress_addresses[recipient_index]);
            let label = format!("reorg-wallet-native-{round}-{wallet_index}");
            phase_all_txids.push(stress_tx_trace(label.clone(), tx.id(), vec![utxo], &accepted_producer_txids));
            parallel_queued.push((label, tx));
            active_stress_wallets.insert(wallet.owner_id_hex.clone());
            submitted_native += 1;
        }

        for wallet_index in 0..stress_wallets.len() {
            let recipient_index = (wallet_index + round as usize + 2) % stress_addresses.len();
            let wallet = &mut stress_wallets[wallet_index];
            let utxo = pop_stress_utxo(&mut wallet.queue, &mut wallet.consumed_outpoints, "reorg wallet messenger tx");
            let tx = build_stress_payload_tx(
                wallet.keypair(),
                &utxo,
                &stress_addresses[recipient_index],
                messenger_payload_v1(900_000 + round * 10_000 + wallet_index as u64, wallet.pubkey_bytes, 192),
            );
            let label = format!("reorg-wallet-messenger-{round}-{wallet_index}");
            phase_all_txids.push(stress_tx_trace(label.clone(), tx.id(), vec![utxo], &accepted_producer_txids));
            parallel_queued.push((label, tx));
            active_stress_wallets.insert(wallet.owner_id_hex.clone());
            submitted_messenger += 1;
        }

        for wallet_index in 0..stress_wallets.len() {
            let recipient_index = (wallet_index + round as usize + 3) % stress_addresses.len();
            let wallet = &mut stress_wallets[wallet_index];
            let utxo = pop_stress_utxo(&mut wallet.queue, &mut wallet.consumed_outpoints, "reorg wallet raw payload tx");
            let mut payload = format!("RAW:reorg-wallet:{round}:{wallet_index}:").into_bytes();
            payload.resize(200 + ((wallet_index % 4) * 80), wallet_index as u8);
            let tx = build_stress_payload_tx(wallet.keypair(), &utxo, &stress_addresses[recipient_index], payload);
            let label = format!("reorg-wallet-raw-{round}-{wallet_index}");
            phase_all_txids.push(stress_tx_trace(label.clone(), tx.id(), vec![utxo], &accepted_producer_txids));
            parallel_queued.push((label, tx));
            active_stress_wallets.insert(wallet.owner_id_hex.clone());
            submitted_raw_payloads += 1;
        }

        for i in 0..4u64 {
            let utxo = pop_stress_utxo(&mut utxo_queue, &mut consumed_outpoints, "reorg stress token create");
            let initial_mint = 1_000u128 + u128::from(round * 4 + i);
            let name = format!("ReorgStress{round:03}{i:02}");
            let symbol = format!("RS{round:03}{i:02}");
            let tx = build_stress_payload_tx(
                owner_keypair(),
                &utxo,
                &owner_address,
                payload_create_asset_with_mint(
                    0,
                    owner_nonce,
                    0,
                    1_000_000_000,
                    owner_id,
                    owner_id,
                    initial_mint,
                    name.as_bytes(),
                    symbol.as_bytes(),
                    b"reorg-stress-created",
                ),
            );
            owner_nonce += 1;
            let label = format!("reorg-create-{round}-{i}");
            let txid = tx.id();
            token_txids.push((label.clone(), txid));
            phase_token_txids.push((label.clone(), txid));
            phase_all_txids.push(stress_tx_trace(label.clone(), txid, vec![utxo], &accepted_producer_txids));
            created_asset_ids.push(txid.to_string());
            ordered_queued.push((label, tx));
            submitted_token_creates += 1;
        }

        for i in 0..2u64 {
            let wallet_index = (round as usize + i as usize) % stress_wallets.len();
            let wallet = &mut stress_wallets[wallet_index];
            let utxo = pop_stress_utxo(&mut wallet.queue, &mut wallet.consumed_outpoints, "reorg wallet token create");
            let name = format!("ReorgWallet{wallet_index:02}{round:03}{i:02}");
            let symbol = format!("RW{wallet_index:02}{round:03}{i:02}");
            let initial_mint = 700u128 + u128::from(round * 2 + i);
            let tx = build_stress_payload_tx(
                wallet.keypair(),
                &utxo,
                &wallet.address,
                payload_create_asset_with_mint(
                    0,
                    wallet.owner_nonce,
                    0,
                    500_000_000,
                    wallet.owner_id,
                    wallet.owner_id,
                    initial_mint,
                    name.as_bytes(),
                    symbol.as_bytes(),
                    b"reorg-wallet-created",
                ),
            );
            wallet.owner_nonce += 1;
            let label = format!("reorg-wallet-create-{round}-{wallet_index}-{i}");
            let txid = tx.id();
            token_txids.push((label.clone(), txid));
            phase_token_txids.push((label.clone(), txid));
            phase_all_txids.push(stress_tx_trace(label.clone(), txid, vec![utxo], &accepted_producer_txids));
            created_asset_ids.push(txid.to_string());
            ordered_queued.push((label, tx));
            active_stress_wallets.insert(wallet.owner_id_hex.clone());
            submitted_token_creates += 1;
            submitted_wallet_token_creates += 1;
        }

        for i in 0..4u64 {
            let mint_amount = 90u128 + u128::from((round + i) % 23);
            let transfer_amount = 15u128 + u128::from((round + i) % 7);
            let burn_amount = 5u128 + u128::from((round + i) % 5);

            let mint_utxo = pop_stress_utxo(&mut utxo_queue, &mut consumed_outpoints, "reorg stress mint");
            let mint_tx = build_stress_payload_tx(
                owner_keypair(),
                &mint_utxo,
                &owner_address,
                payload_mint(0, base_asset_nonce, base_asset_bytes, owner_id, mint_amount),
            );
            base_asset_nonce += 1;
            let mint_label = format!("reorg-mint-{round}-{i}");
            let mint_txid = mint_tx.id();
            token_txids.push((mint_label.clone(), mint_txid));
            phase_token_txids.push((mint_label.clone(), mint_txid));
            phase_all_txids.push(stress_tx_trace(mint_label.clone(), mint_txid, vec![mint_utxo], &accepted_producer_txids));
            ordered_queued.push((mint_label, mint_tx));
            submitted_base_ops += 1;

            let transfer_utxo = pop_stress_utxo(&mut utxo_queue, &mut consumed_outpoints, "reorg stress transfer");
            let recipient_slot = ((round + i) as usize) % (stress_owner_ids.len() + 1);
            let transfer_recipient = if recipient_slot == 0 { receiver_id } else { stress_owner_ids[recipient_slot - 1] };
            let transfer_tx = build_stress_payload_tx(
                owner_keypair(),
                &transfer_utxo,
                &owner_address,
                payload_transfer(0, base_asset_nonce, base_asset_bytes, transfer_recipient, transfer_amount),
            );
            base_asset_nonce += 1;
            let transfer_label = format!("reorg-transfer-{round}-{i}");
            let transfer_txid = transfer_tx.id();
            token_txids.push((transfer_label.clone(), transfer_txid));
            phase_token_txids.push((transfer_label.clone(), transfer_txid));
            phase_all_txids.push(stress_tx_trace(
                transfer_label.clone(),
                transfer_txid,
                vec![transfer_utxo],
                &accepted_producer_txids,
            ));
            ordered_queued.push((transfer_label, transfer_tx));
            submitted_base_ops += 1;

            let burn_utxo = pop_stress_utxo(&mut utxo_queue, &mut consumed_outpoints, "reorg stress burn");
            let burn_tx = build_stress_payload_tx(
                owner_keypair(),
                &burn_utxo,
                &owner_address,
                payload_burn(0, base_asset_nonce, base_asset_bytes, burn_amount),
            );
            base_asset_nonce += 1;
            let burn_label = format!("reorg-burn-{round}-{i}");
            let burn_txid = burn_tx.id();
            token_txids.push((burn_label.clone(), burn_txid));
            phase_token_txids.push((burn_label.clone(), burn_txid));
            phase_all_txids.push(stress_tx_trace(burn_label.clone(), burn_txid, vec![burn_utxo], &accepted_producer_txids));
            ordered_queued.push((burn_label, burn_tx));
            submitted_base_ops += 1;
        }

        let pool_before_buy = client1
            .get_liquidity_pool_state_call(
                None,
                GetLiquidityPoolStateRequest { asset_id: liquidity_asset_id.clone(), at_block_hash: None },
            )
            .await
            .unwrap()
            .pool
            .expect("liquidity pool must exist before reorg stress buy");
        assert_eq!(pool_before_buy.pool_nonce, expected_pool_nonce);
        let pool_vault_value = pool_before_buy.vault_value_sompi.parse::<u64>().unwrap();
        let buy_quote = client1
            .get_liquidity_quote_call(
                None,
                GetLiquidityQuoteRequest {
                    asset_id: liquidity_asset_id.clone(),
                    side: 0,
                    exact_in_amount: "2000000000".to_string(),
                    at_block_hash: None,
                },
            )
            .await
            .unwrap();
        let buy_in_sompi = buy_quote.exact_in_amount.parse::<u64>().unwrap();
        let buy_min_token_out = buy_quote.amount_out.parse::<u128>().unwrap();
        let buy_fee = required_fee(2, 2);
        let buy_utxo =
            pop_stress_utxo_with_min_amount(&mut utxo_queue, &mut consumed_outpoints, "reorg stress buy", buy_in_sompi + buy_fee);
        let buy_change = buy_utxo.1.amount - buy_in_sompi - buy_fee;
        let buy_vault_input = (
            TransactionOutpoint::new(pool_before_buy.vault_txid, pool_before_buy.vault_output_index),
            UtxoEntry::new(pool_vault_value, liquidity_vault_script(), 0, false),
        );
        let buy_tx = build_payload_tx_with_outputs(
            &owner_sk,
            vec![(buy_vault_input.0, buy_vault_input.1.clone(), 0), (buy_utxo.0, buy_utxo.1.clone(), 1)],
            vec![
                TransactionOutput { value: pool_vault_value + buy_in_sompi, script_public_key: liquidity_vault_script() },
                TransactionOutput { value: buy_change, script_public_key: pay_to_address_script(&owner_address) },
            ],
            payload_buy_liquidity(
                1,
                liquidity_asset_nonce,
                liquidity_asset_bytes,
                pool_before_buy.pool_nonce,
                buy_in_sompi,
                buy_min_token_out,
            ),
        );
        liquidity_asset_nonce += 1;
        expected_pool_nonce += 1;
        let buy_label = format!("reorg-liquidity-buy-{round}");
        let buy_txid = buy_tx.id();
        token_txids.push((buy_label.clone(), buy_txid));
        phase_token_txids.push((buy_label.clone(), buy_txid));
        phase_all_txids.push(stress_tx_trace(buy_label.clone(), buy_txid, vec![buy_vault_input, buy_utxo], &accepted_producer_txids));
        ordered_queued.push((buy_label, buy_tx));
        submitted_liquidity_buys += 1;

        let phase_queued = parallel_queued.len() + ordered_queued.len();
        let parallel_submit = tokio::spawn(submit_transactions_parallel_owned(client1.clone(), parallel_queued, 32));
        for (label, tx) in &ordered_queued {
            submit_transaction_and_assert_mempool(&client1, label, tx).await;
        }
        parallel_submit.await.expect("reorg stress parallel submit task panicked");
        let phase_mempool = client1.get_mempool_entries(false, false).await.unwrap();
        max_mempool_entries = max_mempool_entries.max(phase_mempool.len());
        assert!(phase_mempool.len() >= phase_queued, "reorg stress phase did not queue enough txs");

        let phase_chain_start = client1.get_block_dag_info().await.unwrap().sink;
        let (phase_max_block_txs, phase_mined_blocks) = drain_stress_mempool(&client1, &owner_address, "reorg stress phase").await;
        max_block_template_txs = max_block_template_txs.max(phase_max_block_txs);
        mined_stress_blocks += phase_mined_blocks;
        let phase_accepted =
            assert_txids_accepted_since(&client1, phase_chain_start, &phase_all_txids, &format!("reorg stress phase {round}")).await;
        accepted_producer_txids.extend(phase_accepted);
        assert_token_statuses_applied(&client1, &phase_token_txids, &format!("reorg stress phase {round}")).await;

        let pool_after_buy = client1
            .get_liquidity_pool_state_call(
                None,
                GetLiquidityPoolStateRequest { asset_id: liquidity_asset_id.clone(), at_block_hash: None },
            )
            .await
            .unwrap()
            .pool
            .expect("liquidity pool must exist after reorg stress buy");
        assert_eq!(pool_after_buy.pool_nonce, expected_pool_nonce);
        let sell_token_in = 2u128;
        let sell_quote = client1
            .get_liquidity_quote_call(
                None,
                GetLiquidityQuoteRequest {
                    asset_id: liquidity_asset_id.clone(),
                    side: 1,
                    exact_in_amount: sell_token_in.to_string(),
                    at_block_hash: None,
                },
            )
            .await
            .unwrap();
        let sell_cpay_out = sell_quote.amount_out.parse::<u64>().unwrap();
        let sell_fee = required_fee(2, 3);
        let sell_change = buy_change - sell_fee;
        let sell_vault_value = pool_after_buy.vault_value_sompi.parse::<u64>().unwrap() - sell_cpay_out;
        let sell_vault_input = (
            TransactionOutpoint::new(pool_after_buy.vault_txid, pool_after_buy.vault_output_index),
            UtxoEntry::new(pool_after_buy.vault_value_sompi.parse::<u64>().unwrap(), liquidity_vault_script(), 0, false),
        );
        let sell_change_input =
            (TransactionOutpoint::new(buy_txid, 1), UtxoEntry::new(buy_change, pay_to_address_script(&owner_address), 0, false));
        let sell_tx = build_payload_tx_with_outputs(
            &owner_sk,
            vec![(sell_vault_input.0, sell_vault_input.1.clone(), 0), (sell_change_input.0, sell_change_input.1.clone(), 1)],
            vec![
                TransactionOutput { value: sell_vault_value, script_public_key: liquidity_vault_script() },
                TransactionOutput { value: sell_cpay_out, script_public_key: pay_to_address_script(&owner_address) },
                TransactionOutput { value: sell_change, script_public_key: pay_to_address_script(&owner_address) },
            ],
            payload_sell_liquidity(
                1,
                liquidity_asset_nonce,
                liquidity_asset_bytes,
                pool_after_buy.pool_nonce,
                sell_token_in,
                sell_cpay_out,
                1,
            ),
        );
        liquidity_asset_nonce += 1;
        expected_pool_nonce += 1;
        let sell_label = format!("reorg-liquidity-sell-{round}");
        let sell_txid = sell_tx.id();
        token_txids.push((sell_label.clone(), sell_txid));
        let sell_phase_txids =
            vec![stress_tx_trace(sell_label.clone(), sell_txid, vec![sell_vault_input, sell_change_input], &accepted_producer_txids)];
        let sell_phase_token_txids = vec![(sell_label.clone(), sell_txid)];
        submit_transaction_and_assert_mempool(&client1, &sell_label, &sell_tx).await;
        submitted_liquidity_sells += 1;
        let sell_chain_start = client1.get_block_dag_info().await.unwrap().sink;
        let (sell_max_block_txs, sell_mined_blocks) = drain_stress_mempool(&client1, &owner_address, "reorg stress sell").await;
        max_block_template_txs = max_block_template_txs.max(sell_max_block_txs);
        mined_stress_blocks += sell_mined_blocks;
        let sell_accepted =
            assert_txids_accepted_since(&client1, sell_chain_start, &sell_phase_txids, &format!("reorg stress sell {round}")).await;
        accepted_producer_txids.extend(sell_accepted);
        assert_token_statuses_applied(&client1, &sell_phase_token_txids, &format!("reorg stress sell {round}")).await;

        let pool_after_sell = client1
            .get_liquidity_pool_state_call(
                None,
                GetLiquidityPoolStateRequest { asset_id: liquidity_asset_id.clone(), at_block_hash: None },
            )
            .await
            .unwrap()
            .pool
            .expect("liquidity pool must exist after reorg stress sell");
        assert_eq!(pool_after_sell.pool_nonce, expected_pool_nonce);
        let unclaimed_after_sell = pool_after_sell.unclaimed_fee_total_sompi.parse::<u64>().unwrap();
        if round % 2 == 0 && unclaimed_after_sell >= 12_000_000 {
            let claim_amount = 12_000_000u64;
            let claim_fee = required_fee(2, 3);
            let claim_change = sell_change - claim_fee;
            let claim_vault_value = pool_after_sell.vault_value_sompi.parse::<u64>().unwrap() - claim_amount;
            let claim_vault_input = (
                TransactionOutpoint::new(pool_after_sell.vault_txid, pool_after_sell.vault_output_index),
                UtxoEntry::new(pool_after_sell.vault_value_sompi.parse::<u64>().unwrap(), liquidity_vault_script(), 0, false),
            );
            let claim_change_input =
                (TransactionOutpoint::new(sell_txid, 2), UtxoEntry::new(sell_change, pay_to_address_script(&owner_address), 0, false));
            let claim_tx = build_payload_tx_with_outputs(
                &owner_sk,
                vec![(claim_vault_input.0, claim_vault_input.1.clone(), 0), (claim_change_input.0, claim_change_input.1.clone(), 1)],
                vec![
                    TransactionOutput { value: claim_vault_value, script_public_key: liquidity_vault_script() },
                    TransactionOutput { value: claim_amount, script_public_key: pay_to_address_script(&owner_address) },
                    TransactionOutput { value: claim_change, script_public_key: pay_to_address_script(&owner_address) },
                ],
                payload_claim_liquidity(
                    1,
                    liquidity_asset_nonce,
                    liquidity_asset_bytes,
                    pool_after_sell.pool_nonce,
                    0,
                    claim_amount,
                    1,
                ),
            );
            liquidity_asset_nonce += 1;
            expected_pool_nonce += 1;
            let claim_label = format!("reorg-liquidity-claim-{round}");
            let claim_txid = claim_tx.id();
            token_txids.push((claim_label.clone(), claim_txid));
            let claim_phase_txids = vec![stress_tx_trace(
                claim_label.clone(),
                claim_txid,
                vec![claim_vault_input, claim_change_input],
                &accepted_producer_txids,
            )];
            let claim_phase_token_txids = vec![(claim_label.clone(), claim_txid)];
            submit_transaction_and_assert_mempool(&client1, &claim_label, &claim_tx).await;
            submitted_liquidity_claims += 1;
            let claim_chain_start = client1.get_block_dag_info().await.unwrap().sink;
            let (claim_max_block_txs, claim_mined_blocks) = drain_stress_mempool(&client1, &owner_address, "reorg stress claim").await;
            max_block_template_txs = max_block_template_txs.max(claim_max_block_txs);
            mined_stress_blocks += claim_mined_blocks;
            let claim_accepted =
                assert_txids_accepted_since(&client1, claim_chain_start, &claim_phase_txids, &format!("reorg stress claim {round}"))
                    .await;
            accepted_producer_txids.extend(claim_accepted);
            assert_token_statuses_applied(&client1, &claim_phase_token_txids, &format!("reorg stress claim {round}")).await;

            let pool_after_claim = client1
                .get_liquidity_pool_state_call(
                    None,
                    GetLiquidityPoolStateRequest { asset_id: liquidity_asset_id.clone(), at_block_hash: None },
                )
                .await
                .unwrap()
                .pool
                .expect("liquidity pool must exist after reorg stress claim");
            assert_eq!(pool_after_claim.pool_nonce, expected_pool_nonce);
        }
    }

    let remaining = client1.get_mempool_entries(false, false).await.unwrap();
    assert!(remaining.is_empty(), "reorg stress ended losing branch with non-empty mempool: remaining={}", remaining.len());
    assert!(active_stress_wallets.len() == stress_wallets.len(), "not all stress wallets became active");
    assert!(max_mempool_entries >= 50, "reorg stress did not build enough mempool pressure: {max_mempool_entries}");
    assert!(max_block_template_txs >= 45, "reorg stress did not mine a large stress block: {max_block_template_txs}");
    assert!(submitted_native > 0 && submitted_messenger > 0 && submitted_raw_payloads > 0);
    assert!(submitted_token_creates > 0 && submitted_wallet_token_creates > 0 && submitted_base_ops > 0);
    assert!(submitted_liquidity_buys > 0 && submitted_liquidity_sells > 0 && submitted_liquidity_claims > 0);
    assert_token_statuses_applied(&client1, &token_txids, "reorg stress losing branch").await;

    let losing_chain = client1.get_virtual_chain_from_block(pre_stress_sink, true).await.unwrap();
    let losing_blocks = losing_chain.added_chain_block_hashes.len();
    let losing_accepted_txs =
        losing_chain.accepted_transaction_ids.iter().map(|entry| entry.accepted_transaction_ids.len()).sum::<usize>();
    let state_before_reorg = client1.get_token_state_hash_call(None, GetTokenStateHashRequest { at_block_hash: None }).await.unwrap();
    assert_ne!(state_before_reorg.context.state_hash, pre_stress_state.context.state_hash);
    assert_consensus_atomic_hash_exists(&client1, state_before_reorg.context.at_block_hash, "reorg stress losing branch state").await;

    let base_asset_before = client1
        .get_token_asset_call(None, GetTokenAssetRequest { asset_id: base_asset_id.clone(), at_block_hash: None })
        .await
        .unwrap()
        .asset
        .expect("reorg stress base asset must exist before reorg");
    assert!(base_asset_before.total_supply.parse::<u128>().unwrap() > 0);
    let pool_before_reorg = client1
        .get_liquidity_pool_state_call(
            None,
            GetLiquidityPoolStateRequest { asset_id: liquidity_asset_id.clone(), at_block_hash: None },
        )
        .await
        .unwrap()
        .pool
        .expect("reorg stress liquidity pool must exist before reorg");
    assert!(pool_before_reorg.pool_nonce > 1);

    let events_before = client1
        .get_token_events_call(
            None,
            GetTokenEventsRequest { after_sequence: 0, limit: TOKEN_EVENTS_RPC_PAGE_LIMIT, at_block_hash: None },
        )
        .await
        .unwrap();
    let mut applied_event_ids = HashMap::new();
    for (label, txid) in &token_txids {
        let status =
            client1.get_token_op_status_call(None, GetTokenOpStatusRequest { txid: *txid, at_block_hash: None }).await.unwrap();
        assert_eq!(status.apply_status, Some(0), "losing branch token tx {label}/{txid} must be applied before reorg");
        let event = events_before
            .events
            .iter()
            .find(|event| event.txid == *txid && event.apply_status == 0 && event.reorg_of_event_id.is_none())
            .unwrap_or_else(|| panic!("missing applied event before reorg for {label}/{txid}"));
        applied_event_ids.insert(*txid, event.event_id.clone());
    }

    let tip1_count = client1.get_block_dag_info().await.unwrap().block_count;
    while client2.get_block_dag_info().await.unwrap().block_count < tip1_count + 40 {
        mine_blocks(&client2, &winning_owner_address, 1).await;
    }
    let chain2 = client2.get_virtual_chain_from_block(cryptix_consensus::params::SIMNET_GENESIS.hash, true).await.unwrap();
    assert!(chain2.removed_chain_block_hashes.is_empty());
    let winning_blocks = chain2.added_chain_block_hashes;
    let winning_sink = *winning_blocks.last().expect("winning reorg branch must have blocks");
    let winning_block_count = winning_blocks.len();
    for hash in winning_blocks {
        let block = client2.get_block_call(None, GetBlockRequest { hash, include_transactions: true }).await.unwrap().block;
        let raw_block = RpcRawBlock { header: Header::from(&block.header).into(), transactions: block.transactions };
        let _ = client1.submit_block(raw_block, false).await;
    }

    let sink_client = client1.clone();
    wait_for(
        100,
        400,
        move || {
            async fn adopted(client: GrpcClient, expected_sink: cryptix_hashes::Hash) -> bool {
                client.get_block_dag_info().await.map(|info| info.sink == expected_sink).unwrap_or(false)
            }
            Box::pin(adopted(sink_client.clone(), winning_sink))
        },
        "node did not adopt reorg stress winning branch",
    )
    .await;

    let health_after_reorg = wait_for_healthy_atomic_at_sink(&client1, winning_sink, "reorg stress winning branch").await;
    assert_eq!(health_after_reorg.last_applied_block, Some(winning_sink));
    let state_after_reorg = client1.get_token_state_hash_call(None, GetTokenStateHashRequest { at_block_hash: None }).await.unwrap();
    assert_eq!(state_after_reorg.context.at_block_hash, winning_sink);
    assert_eq!(health_after_reorg.state_hash, state_after_reorg.context.state_hash);
    assert_eq!(
        state_after_reorg.context.state_hash, pre_stress_state.context.state_hash,
        "reorg stress winning token-empty branch must restore the exact pre-stress Atomic state"
    );
    assert_ne!(state_after_reorg.context.state_hash, state_before_reorg.context.state_hash);
    assert_consensus_atomic_hash_exists(&client1, winning_sink, "reorg stress winning branch state").await;

    let events_after = client1
        .get_token_events_call(
            None,
            GetTokenEventsRequest { after_sequence: 0, limit: TOKEN_EVENTS_RPC_PAGE_LIMIT, at_block_hash: None },
        )
        .await
        .unwrap();
    for (label, txid) in &token_txids {
        let status =
            client1.get_token_op_status_call(None, GetTokenOpStatusRequest { txid: *txid, at_block_hash: None }).await.unwrap();
        assert!(status.apply_status.is_none(), "reorged token tx {label}/{txid} must not keep an op status");
        let applied_event_id = applied_event_ids.get(txid).expect("applied event id must be captured before reorg");
        assert!(
            events_after.events.iter().any(|event| {
                event.txid == *txid && event.event_type == 2 && event.reorg_of_event_id.as_deref() == Some(applied_event_id.as_str())
            }),
            "missing reorged event for stress tx {label}/{txid}"
        );
    }

    for asset_id in &created_asset_ids {
        let asset = client1
            .get_token_asset_call(None, GetTokenAssetRequest { asset_id: asset_id.clone(), at_block_hash: None })
            .await
            .unwrap();
        assert!(asset.asset.is_none(), "reorged stress asset {asset_id} must disappear after reorg");
    }
    for owner in std::iter::once(owner_id_hex.clone())
        .chain(std::iter::once(receiver_id_hex.clone()))
        .chain(stress_wallets.iter().map(|wallet| wallet.owner_id_hex.clone()))
    {
        let balance = client1
            .get_token_balance_call(
                None,
                GetTokenBalanceRequest { asset_id: base_asset_id.clone(), owner_id: owner, at_block_hash: None },
            )
            .await
            .unwrap();
        assert_eq!(balance.balance, "0", "reorged base asset balance must be zero");
    }
    let owner_nonce_after = client1
        .get_token_nonce_call(None, GetTokenNonceRequest { owner_id: owner_id_hex.clone(), asset_id: None, at_block_hash: None })
        .await
        .unwrap();
    assert_eq!(owner_nonce_after.expected_next_nonce, 1);
    for wallet in &stress_wallets {
        let nonce_after = client1
            .get_token_nonce_call(
                None,
                GetTokenNonceRequest { owner_id: wallet.owner_id_hex.clone(), asset_id: None, at_block_hash: None },
            )
            .await
            .unwrap();
        assert_eq!(nonce_after.expected_next_nonce, 1, "{} owner nonce must reset after reorg", wallet.label);
    }

    for _ in 0..80 {
        if client1.get_mempool_entries(false, false).await.unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let remaining_after_reorg = client1.get_mempool_entries(false, false).await.unwrap();
    assert!(remaining_after_reorg.is_empty(), "reorg stress left stale transactions in mempool: {}", remaining_after_reorg.len());

    let winner_utxos = fetch_spendable_utxos(&client1, winning_owner_address.clone(), coinbase_maturity).await;
    assert!(!winner_utxos.is_empty(), "winning branch must fund the post-reorg owner");
    let fresh_create_tx = build_payload_tx(
        Keypair::from_secret_key(secp256k1::SECP256K1, &winning_owner_sk),
        &winner_utxos[0],
        &winning_owner_address,
        payload_create_asset(0, 1, 0, winning_owner_id, b"ReorgStressAfter", b"RSA", b"winning-branch"),
    );
    let fresh_asset_id = fresh_create_tx.id().to_string();
    submit_and_wait_indexed(&client1, &fresh_create_tx, &winning_owner_address).await;
    let fresh_asset = client1
        .get_token_asset_call(None, GetTokenAssetRequest { asset_id: fresh_asset_id, at_block_hash: None })
        .await
        .unwrap()
        .asset
        .expect("fresh post-reorg stress asset must exist");
    assert_eq!(fresh_asset.symbol, "RSA");
    let winner_nonce_after_fresh = client1
        .get_token_nonce_call(None, GetTokenNonceRequest { owner_id: winning_owner_id_hex, asset_id: None, at_block_hash: None })
        .await
        .unwrap();
    assert_eq!(winner_nonce_after_fresh.expected_next_nonce, 2);

    println!(
        "reorg stress summary: rounds={} wallets={} active_wallets={} native={} messenger={} raw_payloads={} token_creates={} wallet_token_creates={} base_ops={} buys={} sells={} claims={} token_txs={} losing_blocks={} losing_accepted_txs={} winning_blocks={} max_mempool_entries={} max_block_template_txs={} mined_stress_blocks={} before_hash={} after_hash={}",
        rounds,
        stress_wallets.len(),
        active_stress_wallets.len(),
        submitted_native,
        submitted_messenger,
        submitted_raw_payloads,
        submitted_token_creates,
        submitted_wallet_token_creates,
        submitted_base_ops,
        submitted_liquidity_buys,
        submitted_liquidity_sells,
        submitted_liquidity_claims,
        token_txids.len(),
        losing_blocks,
        losing_accepted_txs,
        winning_block_count,
        max_mempool_entries,
        max_block_template_txs,
        mined_stress_blocks,
        state_before_reorg.context.state_hash,
        state_after_reorg.context.state_hash
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn atomic_token_atomic_enabled_rpc_smoke_simulate_and_snapshot() {
    cryptix_core::log::try_init_logger("INFO");
    let mut daemon = Daemon::new_random_with_args(atomic_args(), 10);
    let client = daemon.start().await;
    let (owner_sk, owner_pk) = secp256k1::generate_keypair(&mut thread_rng());
    let owner_address = Address::new(daemon.network.into(), Version::PubKey, &owner_pk.x_only_public_key().0.serialize());
    let (_recv_sk, recv_pk) = secp256k1::generate_keypair(&mut thread_rng());
    let receiver_address = Address::new(daemon.network.into(), Version::PubKey, &recv_pk.x_only_public_key().0.serialize());
    let owner_id = owner_id_from_address(&owner_address);
    let receiver_id = owner_id_from_address(&receiver_address);
    let owner_id_hex = hex32(owner_id);
    let receiver_id_hex = hex32(receiver_id);
    let coinbase_maturity = daemon.args.read().coinbase_maturity_override.unwrap_or(SIMNET_PARAMS.coinbase_maturity);

    let mut utxos = mine_until_spendable_utxos(&client, &owner_address, coinbase_maturity, 4).await;
    utxos.truncate(4);

    let create_tx = build_payload_tx(
        Keypair::from_secret_key(secp256k1::SECP256K1, &owner_sk),
        &utxos[0],
        &owner_address,
        payload_create_asset(0, 1, 8, owner_id, b"SmokeToken", b"SMK", b"\x01"),
    );
    submit_and_wait_indexed(&client, &create_tx, &owner_address).await;
    let asset_id = create_tx.id().to_string();
    let asset_id_bytes = create_tx.id().as_bytes();

    let mint_tx = build_payload_tx(
        Keypair::from_secret_key(secp256k1::SECP256K1, &owner_sk),
        &utxos[1],
        &owner_address,
        payload_mint(0, 1, asset_id_bytes, owner_id, 1000),
    );
    submit_and_wait_indexed(&client, &mint_tx, &owner_address).await;

    let transfer_tx = build_payload_tx(
        Keypair::from_secret_key(secp256k1::SECP256K1, &owner_sk),
        &utxos[2],
        &owner_address,
        payload_transfer(0, 2, asset_id_bytes, receiver_id, 300),
    );
    submit_and_wait_indexed(&client, &transfer_tx, &owner_address).await;

    let burn_tx = build_payload_tx(
        Keypair::from_secret_key(secp256k1::SECP256K1, &owner_sk),
        &utxos[3],
        &owner_address,
        payload_burn(0, 3, asset_id_bytes, 200),
    );
    submit_and_wait_indexed(&client, &burn_tx, &owner_address).await;

    let tracked_txids = vec![create_tx.id(), mint_tx.id(), transfer_tx.id(), burn_tx.id()];

    let health = client.get_token_health_call(None, GetTokenHealthRequest { at_block_hash: None }).await.unwrap();
    assert!(!health.is_degraded);
    assert!(!health.bootstrap_in_progress);

    let state_hash_before = client.get_token_state_hash_call(None, GetTokenStateHashRequest { at_block_hash: None }).await.unwrap();
    assert!(!state_hash_before.context.state_hash.is_empty());

    let owner_balance_before = client
        .get_token_balance_call(
            None,
            GetTokenBalanceRequest { asset_id: asset_id.clone(), owner_id: owner_id_hex.clone(), at_block_hash: None },
        )
        .await
        .unwrap();
    let receiver_balance_before = client
        .get_token_balance_call(
            None,
            GetTokenBalanceRequest { asset_id: asset_id.clone(), owner_id: receiver_id_hex.clone(), at_block_hash: None },
        )
        .await
        .unwrap();
    let owner_nonce_before = client
        .get_token_nonce_call(None, GetTokenNonceRequest { owner_id: owner_id_hex.clone(), asset_id: None, at_block_hash: None })
        .await
        .unwrap();
    let receiver_nonce_before = client
        .get_token_nonce_call(None, GetTokenNonceRequest { owner_id: receiver_id_hex.clone(), asset_id: None, at_block_hash: None })
        .await
        .unwrap();
    let events_before = client
        .get_token_events_call(None, GetTokenEventsRequest { after_sequence: 0, limit: 1000, at_block_hash: None })
        .await
        .unwrap();
    assert!(events_before.events.len() >= tracked_txids.len());
    for txid in &tracked_txids {
        assert!(events_before.events.iter().any(|event| event.txid == *txid), "missing token event for tx {txid}");
    }
    let events_before_fingerprint = events_before
        .events
        .iter()
        .map(|event| {
            format!(
                "{}|{}|{}|{}|{}|{}|{}|{}|{}",
                event.event_id,
                event.sequence,
                event.accepting_block_hash,
                event.txid,
                event.event_type,
                event.apply_status,
                event.noop_reason,
                event.ordinal,
                event.reorg_of_event_id.clone().unwrap_or_default()
            )
        })
        .collect::<Vec<_>>();
    let mut op_status_before = Vec::with_capacity(tracked_txids.len());
    for txid in &tracked_txids {
        let status =
            client.get_token_op_status_call(None, GetTokenOpStatusRequest { txid: *txid, at_block_hash: None }).await.unwrap();
        assert_eq!(status.apply_status, Some(0), "unexpected pre-import op status for tx {txid}");
        op_status_before.push((*txid, status.accepting_block_hash, status.apply_status, status.noop_reason));
    }

    let snapshot_dir = tempfile::tempdir().unwrap();
    let snapshot_path: PathBuf = snapshot_dir.path().join("atomic-smoke.snapshot");
    client
        .export_token_snapshot_call(None, ExportTokenSnapshotRequest { path: snapshot_path.to_string_lossy().to_string() })
        .await
        .unwrap();

    let snapshot_head = client.get_sc_snapshot_head_call(None, GetScSnapshotHeadRequest {}).await.unwrap();
    let head = snapshot_head.head.expect("snapshot head should exist after export");
    assert!(!head.snapshot_id.is_empty());
    assert!(!head.state_hash_at_fp.is_empty());

    let sources = client.get_sc_bootstrap_sources_call(None, GetScBootstrapSourcesRequest {}).await.unwrap();
    assert!(!sources.sources.is_empty());
    assert!(sources.sources.iter().any(|source| source.snapshot_id == head.snapshot_id));

    let manifest = client
        .get_sc_snapshot_manifest_call(None, GetScSnapshotManifestRequest { snapshot_id: head.snapshot_id.clone() })
        .await
        .unwrap();
    assert_eq!(manifest.snapshot_id, head.snapshot_id);
    assert!(!manifest.manifest_hex.is_empty());

    let snapshot_chunk = client
        .get_sc_snapshot_chunk_call(
            None,
            GetScSnapshotChunkRequest { snapshot_id: head.snapshot_id.clone(), chunk_index: 0, chunk_size: None },
        )
        .await
        .unwrap();
    assert_eq!(snapshot_chunk.chunk_index, 0);
    assert!(!snapshot_chunk.chunk_hex.is_empty());

    let replay_chunk = client
        .get_sc_replay_window_chunk_call(
            None,
            GetScReplayWindowChunkRequest { snapshot_id: head.snapshot_id, chunk_index: 0, chunk_size: None },
        )
        .await
        .unwrap();
    assert_eq!(replay_chunk.chunk_index, 0);
    assert!(!replay_chunk.chunk_hex.is_empty());

    client
        .import_token_snapshot_call(None, ImportTokenSnapshotRequest { path: snapshot_path.to_string_lossy().to_string() })
        .await
        .unwrap();

    let state_hash_after = client.get_token_state_hash_call(None, GetTokenStateHashRequest { at_block_hash: None }).await.unwrap();
    assert_eq!(state_hash_after.context.state_hash, state_hash_before.context.state_hash);

    let owner_balance_after = client
        .get_token_balance_call(
            None,
            GetTokenBalanceRequest { asset_id: asset_id.clone(), owner_id: owner_id_hex.clone(), at_block_hash: None },
        )
        .await
        .unwrap();
    let receiver_balance_after = client
        .get_token_balance_call(None, GetTokenBalanceRequest { asset_id, owner_id: receiver_id_hex.clone(), at_block_hash: None })
        .await
        .unwrap();
    assert_eq!(owner_balance_after.balance, owner_balance_before.balance);
    assert_eq!(receiver_balance_after.balance, receiver_balance_before.balance);

    let owner_nonce_after = client
        .get_token_nonce_call(None, GetTokenNonceRequest { owner_id: owner_id_hex.clone(), asset_id: None, at_block_hash: None })
        .await
        .unwrap();
    let receiver_nonce_after = client
        .get_token_nonce_call(None, GetTokenNonceRequest { owner_id: receiver_id_hex.clone(), asset_id: None, at_block_hash: None })
        .await
        .unwrap();
    assert_eq!(owner_nonce_after.expected_next_nonce, owner_nonce_before.expected_next_nonce);
    assert_eq!(receiver_nonce_after.expected_next_nonce, receiver_nonce_before.expected_next_nonce);

    let events_after = client
        .get_token_events_call(None, GetTokenEventsRequest { after_sequence: 0, limit: 1000, at_block_hash: None })
        .await
        .unwrap();
    let events_after_fingerprint = events_after
        .events
        .iter()
        .map(|event| {
            format!(
                "{}|{}|{}|{}|{}|{}|{}|{}|{}",
                event.event_id,
                event.sequence,
                event.accepting_block_hash,
                event.txid,
                event.event_type,
                event.apply_status,
                event.noop_reason,
                event.ordinal,
                event.reorg_of_event_id.clone().unwrap_or_default()
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(events_after_fingerprint, events_before_fingerprint);

    for (txid, accepting_block_hash, apply_status, noop_reason) in op_status_before {
        let status_after = client.get_token_op_status_call(None, GetTokenOpStatusRequest { txid, at_block_hash: None }).await.unwrap();
        assert_eq!(status_after.accepting_block_hash, accepting_block_hash);
        assert_eq!(status_after.apply_status, apply_status);
        assert_eq!(status_after.noop_reason, noop_reason);
    }

    let health_after_import = client.get_token_health_call(None, GetTokenHealthRequest { at_block_hash: None }).await.unwrap();
    assert!(!health_after_import.bootstrap_in_progress);
    assert_eq!(health_after_import.state_hash, state_hash_before.context.state_hash);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn atomic_token_atomic_enabled_snapshot_import_rejects_tampered_snapshot() {
    cryptix_core::log::try_init_logger("INFO");
    let mut daemon = Daemon::new_random_with_args(atomic_args(), 10);
    let client = daemon.start().await;

    let (_owner_sk, owner_pk) = secp256k1::generate_keypair(&mut thread_rng());
    let owner_address = Address::new(daemon.network.into(), Version::PubKey, &owner_pk.x_only_public_key().0.serialize());
    mine_blocks(&client, &owner_address, 2).await;

    let snapshot_dir = tempfile::tempdir().unwrap();
    let snapshot_path: PathBuf = snapshot_dir.path().join("atomic-tampered.snapshot");
    client
        .export_token_snapshot_call(None, ExportTokenSnapshotRequest { path: snapshot_path.to_string_lossy().to_string() })
        .await
        .unwrap();
    let state_hash_before = client.get_token_state_hash_call(None, GetTokenStateHashRequest { at_block_hash: None }).await.unwrap();

    let mut snapshot_bytes = fs::read(&snapshot_path).unwrap();
    assert!(!snapshot_bytes.is_empty());
    snapshot_bytes[0] ^= 0x01;
    fs::write(&snapshot_path, &snapshot_bytes).unwrap();

    let import_err = client
        .import_token_snapshot_call(None, ImportTokenSnapshotRequest { path: snapshot_path.to_string_lossy().to_string() })
        .await
        .unwrap_err();
    assert!(import_err.to_string().contains("snapshot import failed"), "expected snapshot import failure, got: {import_err}");

    let health = client.get_token_health_call(None, GetTokenHealthRequest { at_block_hash: None }).await.unwrap();
    assert!(!health.is_degraded);
    assert_eq!(health.token_state, "healthy");
    assert!(!health.bootstrap_in_progress);
    let state_hash_after = client.get_token_state_hash_call(None, GetTokenStateHashRequest { at_block_hash: None }).await.unwrap();
    assert_eq!(state_hash_after.context.state_hash, state_hash_before.context.state_hash);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn atomic_token_atomic_enabled_snapshot_import_rejects_truncated_snapshot() {
    cryptix_core::log::try_init_logger("INFO");
    let mut daemon = Daemon::new_random_with_args(atomic_args(), 10);
    let client = daemon.start().await;

    let (_owner_sk, owner_pk) = secp256k1::generate_keypair(&mut thread_rng());
    let owner_address = Address::new(daemon.network.into(), Version::PubKey, &owner_pk.x_only_public_key().0.serialize());
    mine_blocks(&client, &owner_address, 2).await;

    let snapshot_dir = tempfile::tempdir().unwrap();
    let snapshot_path: PathBuf = snapshot_dir.path().join("atomic-truncated.snapshot");
    client
        .export_token_snapshot_call(None, ExportTokenSnapshotRequest { path: snapshot_path.to_string_lossy().to_string() })
        .await
        .unwrap();
    let state_hash_before = client.get_token_state_hash_call(None, GetTokenStateHashRequest { at_block_hash: None }).await.unwrap();

    let snapshot_bytes = fs::read(&snapshot_path).unwrap();
    let trunc_len = usize::max(1, snapshot_bytes.len() / 2);
    fs::write(&snapshot_path, &snapshot_bytes[..trunc_len]).unwrap();

    let import_err = client
        .import_token_snapshot_call(None, ImportTokenSnapshotRequest { path: snapshot_path.to_string_lossy().to_string() })
        .await
        .unwrap_err();
    assert!(import_err.to_string().contains("snapshot import failed"), "expected snapshot import failure, got: {import_err}");

    let health = client.get_token_health_call(None, GetTokenHealthRequest { at_block_hash: None }).await.unwrap();
    assert!(!health.is_degraded);
    assert_eq!(health.token_state, "healthy");
    assert!(!health.bootstrap_in_progress);
    let state_hash_after = client.get_token_state_hash_call(None, GetTokenStateHashRequest { at_block_hash: None }).await.unwrap();
    assert_eq!(state_hash_after.context.state_hash, state_hash_before.context.state_hash);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn atomic_token_atomic_enabled_snapshot_import_rejects_wrong_chain_snapshot() {
    cryptix_core::log::try_init_logger("INFO");
    let mut daemon_source = Daemon::new_random_with_args(atomic_args(), 10);
    let mut daemon_target = Daemon::new_random_with_args(atomic_args(), 10);
    let source_client = daemon_source.start().await;
    let target_client = daemon_target.start().await;

    let (_source_sk, source_pk) = secp256k1::generate_keypair(&mut thread_rng());
    let source_miner = Address::new(daemon_source.network.into(), Version::PubKey, &source_pk.x_only_public_key().0.serialize());
    mine_blocks(&source_client, &source_miner, 4).await;

    let snapshot_dir = tempfile::tempdir().unwrap();
    let snapshot_path: PathBuf = snapshot_dir.path().join("atomic-wrong-chain.snapshot");
    source_client
        .export_token_snapshot_call(None, ExportTokenSnapshotRequest { path: snapshot_path.to_string_lossy().to_string() })
        .await
        .unwrap();

    let import_err = target_client
        .import_token_snapshot_call(None, ImportTokenSnapshotRequest { path: snapshot_path.to_string_lossy().to_string() })
        .await
        .unwrap_err();
    assert!(
        import_err.to_string().contains("snapshot import failed") || import_err.to_string().contains("cannot find header"),
        "expected wrong-chain snapshot import failure, got: {import_err}"
    );

    match target_client.get_token_health_call(None, GetTokenHealthRequest { at_block_hash: None }).await {
        Ok(health) => {
            assert!(!health.is_degraded);
            assert!(!health.bootstrap_in_progress);
        }
        Err(err) if is_temporarily_atomic_unready(&err) => {}
        Err(err) => panic!("unexpected token health error after wrong-chain import rejection: {err}"),
    }
}
