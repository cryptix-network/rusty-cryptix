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
        MutableTransaction, ScriptPublicKey, ScriptVec, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput,
        UtxoEntry,
    },
};
use cryptix_grpc_client::GrpcClient;
use cryptix_rpc_core::{api::rpc::RpcApi, model::*};
use cryptix_txscript::pay_to_address_script;
use cryptixd_lib::args::Args;
use rand::thread_rng;
use secp256k1::Keypair;
use std::{fs, path::PathBuf, time::Duration};

const CAT_OWNER_DOMAIN: &[u8] = b"CAT_OWNER_V2";
const CURRENT_TOKEN_VERSION: u8 = 1;
const CURRENT_LIQUIDITY_CURVE_VERSION: u8 = 1;
const LIQUIDITY_TOKEN_SUPPLY_RAW: u128 = 1_000_000;
const MIN_LIQUIDITY_SEED_RESERVE_SOMPI: u64 = SOMPI_PER_CRYPTIX;
const OWNER_AUTH_SCHEME_PUBKEY: u8 = 0;
const OWNER_AUTH_SCHEME_PUBKEY_ECDSA: u8 = 1;
const ATOMIC_TEST_PAYLOAD_HF_DAA: u64 = 2;

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

fn payload_create_liquidity(
    auth_input_index: u16,
    nonce: u64,
    max_supply: u128,
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
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.push(0);
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
    let mut payload = base_header(6, auth_input_index, nonce);
    payload.extend_from_slice(&asset_id);
    payload.extend_from_slice(&expected_pool_nonce.to_le_bytes());
    payload.extend_from_slice(&cpay_in_sompi.to_le_bytes());
    payload.extend_from_slice(&min_token_out.to_le_bytes());
    payload
}

fn liquidity_vault_script() -> ScriptPublicKey {
    ScriptPublicKey::new(0, ScriptVec::from_slice(&[0x04, b'C', b'L', b'V', b'1', 0x75, 0x51]))
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

async fn mine_until_spendable_utxos(
    client: &GrpcClient,
    address: &Address,
    coinbase_maturity: u64,
    min_utxos: usize,
) -> Vec<(TransactionOutpoint, UtxoEntry)> {
    for _ in 0..300 {
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

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
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

    let mut utxos = mine_until_spendable_utxos(&client, &owner_address, coinbase_maturity, 70).await;
    utxos.truncate(70);

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
    let liquidity_create_tx = build_payload_tx_with_outputs(
        &owner_sk,
        vec![(utxos[1].0, utxos[1].1.clone(), 1)],
        vec![
            TransactionOutput { value: liquidity_vault_value, script_public_key: liquidity_vault_script() },
            TransactionOutput { value: liquidity_change, script_public_key: pay_to_address_script(&owner_address) },
        ],
        payload_create_liquidity(0, 2, LIQUIDITY_TOKEN_SUPPLY_RAW, 0, 0, b"StressPool", b"STP"),
    );
    submit_and_wait_indexed(&client, &liquidity_create_tx, &owner_address).await;
    let liquidity_asset_id = liquidity_create_tx.id().to_string();
    let liquidity_asset_bytes = liquidity_create_tx.id().as_bytes();

    let mut queued = Vec::new();
    let mut token_txids = Vec::new();
    let mut next_utxo = 2usize;
    let mut asset_nonce = 1u64;
    let mut owner_nonce = 3u64;

    for i in 0..12 {
        let native_tx = build_native_tx(owner_keypair(), &utxos[next_utxo], &owner_address);
        next_utxo += 1;
        queued.push((format!("native-{i}"), native_tx, false));

        let messenger_tx = build_payload_tx(
            owner_keypair(),
            &utxos[next_utxo],
            &owner_address,
            format!("MSG:atomic-stress:{i}:{}", "x".repeat(128)).into_bytes(),
        );
        next_utxo += 1;
        queued.push((format!("messenger-{i}"), messenger_tx, false));

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
        queued.push((format!("create-{i}"), create_tx, true));

        if i < 8 {
            let mint_tx = build_payload_tx(
                owner_keypair(),
                &utxos[next_utxo],
                &owner_address,
                payload_mint(0, asset_nonce, base_asset_bytes, owner_id, 100),
            );
            next_utxo += 1;
            token_txids.push((format!("mint-{i}"), mint_tx.id()));
            queued.push((format!("mint-{i}"), mint_tx, true));
            asset_nonce += 1;

            let transfer_tx = build_payload_tx(
                owner_keypair(),
                &utxos[next_utxo],
                &owner_address,
                payload_transfer(0, asset_nonce, base_asset_bytes, receiver_id, 30),
            );
            next_utxo += 1;
            token_txids.push((format!("transfer-{i}"), transfer_tx.id()));
            queued.push((format!("transfer-{i}"), transfer_tx, true));
            asset_nonce += 1;

            let burn_tx = build_payload_tx(
                owner_keypair(),
                &utxos[next_utxo],
                &owner_address,
                payload_burn(0, asset_nonce, base_asset_bytes, 10),
            );
            next_utxo += 1;
            token_txids.push((format!("burn-{i}"), burn_tx.id()));
            queued.push((format!("burn-{i}"), burn_tx, true));
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
    let buy_in_sompi = 833_336_112;
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
        payload_buy_liquidity(1, 1, liquidity_asset_bytes, pool_before.pool_nonce, buy_in_sompi, 1),
    );
    token_txids.push(("liquidity-buy-0".to_string(), buy_tx.id()));
    queued.push(("liquidity-buy-0".to_string(), buy_tx, true));

    for (label, tx, _) in &queued {
        client.submit_transaction(tx.into(), false).await.unwrap_or_else(|err| panic!("submit {label} failed: {err}"));
        client.get_mempool_entry(tx.id(), false, false).await.unwrap_or_else(|err| panic!("missing mempool entry for {label}: {err}"));
    }
    let mempool_entries = client.get_mempool_entries(false, false).await.unwrap();
    assert!(
        mempool_entries.len() >= queued.len(),
        "mempool did not retain queued stress load: queued={} entries={}",
        queued.len(),
        mempool_entries.len()
    );

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
    assert!(remaining.is_empty(), "mempool did not drain after stress mining: remaining={}", remaining.len());

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

    let owner_balance = client
        .get_token_balance_call(
            None,
            GetTokenBalanceRequest { asset_id: base_asset_id.clone(), owner_id: owner_id_hex.clone(), at_block_hash: None },
        )
        .await
        .unwrap();
    assert_eq!(owner_balance.balance, "20480");
    let receiver_balance = client
        .get_token_balance_call(
            None,
            GetTokenBalanceRequest { asset_id: base_asset_id.clone(), owner_id: receiver_id_hex.clone(), at_block_hash: None },
        )
        .await
        .unwrap();
    assert_eq!(receiver_balance.balance, "240");

    let base_asset = client
        .get_token_asset_call(None, GetTokenAssetRequest { asset_id: base_asset_id.clone(), at_block_hash: None })
        .await
        .unwrap()
        .asset
        .expect("base asset must exist after stress run");
    assert_eq!(base_asset.total_supply, "20720");

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
    assert_eq!(liquidity_asset_nonce_after.expected_next_nonce, 2);

    let assets = client
        .get_token_assets_call(None, GetTokenAssetsRequest { offset: 0, limit: 100, query: None, at_block_hash: None })
        .await
        .unwrap();
    assert!(assets.total >= 14, "expected stress run to create at least 14 token assets, got {}", assets.total);

    let pool_after = client
        .get_liquidity_pool_state_call(
            None,
            GetLiquidityPoolStateRequest { asset_id: liquidity_asset_id.clone(), at_block_hash: None },
        )
        .await
        .unwrap()
        .pool
        .expect("liquidity pool must exist after queued buy");
    assert_eq!(pool_after.pool_nonce, pool_before.pool_nonce + 1);
    assert!(pool_after.total_supply.parse::<u128>().unwrap() > 0);
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
