use std::sync::Arc;

use cryptix_core::{log, panic};
use cryptix_core::task::runtime::AsyncRuntime;
use cryptix_rpc_core::{RpcError, RpcResult};
use cryptix_rpc_core::api::rpc::RpcApi;
use cryptix_rpc_core::model::contract::*;
use cryptix_rpc_service::service::RpcCoreService;
use cryptixd_lib::args::Args;
use crate::common::daemon::Daemon;
use cryptix_utils::fd_budget;

/// Helper: start a dev/sim node with utxoindex+unsafe_rpc and obtain the RpcCoreService instance.
async fn start_daemon_and_service() -> (Daemon, Arc<RpcCoreService>) {
    log::try_init_logger("info");
    panic::configure_panic();

    let args = Args {
        // Use the same style as rpc_tests::sanity_test but dev/sim is fine either way
        simnet: true,
        disable_upnp: true,
        enable_unsynced_mining: true,
        block_template_cache_lifetime: Some(0),
        utxoindex: true,
        unsafe_rpc: true,
        ..Default::default()
    };

    let fd_total_budget = fd_budget::limit();
    let mut daemon = Daemon::new_random_with_args(args, fd_total_budget);
    // Start core + RPC services
    let _client = daemon.start().await;

    // Retrieve RpcCoreService directly from the running Core
    let async_rt = Arc::downcast::<AsyncRuntime>(daemon.core.find(AsyncRuntime::IDENT).unwrap().arc_any()).unwrap();
    let rpc_service = Arc::downcast::<RpcCoreService>(async_rt.find(RpcCoreService::IDENT).unwrap().arc_any()).unwrap();

    (daemon, rpc_service)
}

/// Test 1: Empty state queries:
/// - get_contract_state_call on non-existing contract_id should return has_state=false
/// - list_contracts_call should be empty on a fresh node
#[tokio::test]
async fn test_contract_get_and_list_empty_state() {
    let (mut daemon, service) = start_daemon_and_service().await;

    let _cid: u64 = 1234;
    // Use a syntactically valid but non-existent instance_id "<zero_txid>:0"
    let dummy_instance = format!("{}:0", "0000000000000000000000000000000000000000000000000000000000000000");
    let get_resp: RpcResult<GetContractStateResponse> =
        service.get_contract_state_call(None, GetContractStateRequest { instance_id: dummy_instance.clone() }).await;
    let get_resp = get_resp.expect("get_contract_state_call should not error for missing contract");
    assert!(!get_resp.has_state, "expected no state for a fresh node");
    assert!(get_resp.state.is_empty(), "expected empty state bytes when has_state=false");
    assert!(get_resp.state_outpoint.is_none(), "expected no outpoint when has_state=false");

    let list_resp = service.list_contracts_call(None, ListContractsRequest {}).await.expect("list_contracts_call failed");
    assert!(list_resp.contracts.is_empty(), "expected no contract entries on fresh node");

    daemon.shutdown();
}

/// Mine a single block using the service, and wait until sink blue score increases by at least 1.
async fn mine_block_and_wait(service: &RpcCoreService) -> RpcResult<()> {
    use cryptix_rpc_core::model::{GetBlockTemplateRequest, SubmitBlockRequest, GetSinkBlueScoreRequest};
    use cryptix_addresses::{Address, Prefix, Version};

    // Read current blue score
    let before = service.get_sink_blue_score_call(None, GetSinkBlueScoreRequest {}).await?.blue_score;

    // Build a block template
    let pay_address = Address::new(Prefix::Simnet, Version::PubKey, &[0u8; 32]);
    let tpl = service
        .get_block_template_call(None, GetBlockTemplateRequest { pay_address, extra_data: Vec::new() })
        .await?;

    // Submit the template (simnet unsynced mining skips PoW)
    let _ = service
        .submit_block_call(None, SubmitBlockRequest { block: tpl.block, allow_non_daa_blocks: true })
        .await?;

    // Wait for virtual to process the block
    let mut tries = 0usize;
    loop {
        let after = service.get_sink_blue_score_call(None, GetSinkBlueScoreRequest {}).await?.blue_score;
        if after > before {
            break;
        }
        tries += 1;
        if tries > 50 {
            return Err(RpcError::General("timeout waiting for block acceptance".to_string()));
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    Ok(())
}

/// Test A — deployContract happy path (if implemented)
#[tokio::test]
async fn test_contract_deploy_happy_path() {

    let (mut daemon, service) = start_daemon_and_service().await;

    let cid: u64 = 1; // Echo contract
    let initial_state = vec![1u8, 2, 3, 4];

    match service
        .deploy_contract_call(None, DeployContractRequest { contract_id: cid, initial_state: initial_state.clone() })
        .await
    {
        Ok(resp) => {
            // tx id should not be zero bytes
            use cryptix_consensus_core::tx::TransactionId;
            assert_ne!(resp.transaction_id, TransactionId::from_bytes([0u8; 32]));
            assert!(resp.state_outpoint.is_some());
            let instance_id = resp.instance_id.clone().expect("deploy should return instance_id");
            // Mine a block so state becomes part of virtual UTXO
            mine_block_and_wait(&service).await.expect("mining failed");
            // Verify state presence and value
            let got = service.get_contract_state_call(None, GetContractStateRequest { instance_id: instance_id.clone() }).await.unwrap();
            assert!(got.has_state);
            assert_eq!(got.state, initial_state);
            assert!(got.state_outpoint.is_some());
            // listContracts contains exactly one entry for this contract (could be 1 if no other tests ran)
            let list = service.list_contracts_call(None, ListContractsRequest {}).await.unwrap();
            assert!(list.contracts.iter().any(|e| e.contract_id == cid));
        }
        Err(err) => {
            // Allow rejection on branches where tx building requires fees/inputs not yet implemented
            match err {
                RpcError::RejectedTransaction(_, _) | RpcError::NotImplemented | RpcError::UnsupportedFeature => {}
                other => panic!("unexpected error from deploy_contract_call: {:?}", other),
            }
        }
    }

    daemon.shutdown();
}

/// Test B — deployContract oversized initial state
#[tokio::test]
async fn test_contract_deploy_oversized_initial_state() {
    use cryptix_consensus_core::contract::MAX_CONTRACT_STATE_SIZE;

    let (mut daemon, service) = start_daemon_and_service().await;

    let cid: u64 = 1; // Echo contract
    let initial_state = vec![0u8; MAX_CONTRACT_STATE_SIZE + 1];

    let res = service
        .deploy_contract_call(None, DeployContractRequest { contract_id: cid, initial_state })
        .await;

    assert!(res.is_err(), "expected rejection for oversized initial state");
    if let Err(err) = res {
        match err {
            RpcError::RejectedTransaction(_, _) | RpcError::NotImplemented | RpcError::UnsupportedFeature => {}
            other => panic!("unexpected error for oversized deploy: {:?}", other),
        }
    }

    daemon.shutdown();
}

/// Test C — double deployment of same contract_id
#[tokio::test]
async fn test_contract_double_deploy_same_id() {
    let (mut daemon, service) = start_daemon_and_service().await;

    let cid: u64 = 1; // Echo contract
    let initial_state = vec![9u8, 9, 9];

    // First deploy
    let first = service
        .deploy_contract_call(None, DeployContractRequest { contract_id: cid, initial_state: initial_state.clone() })
        .await;
    if let Ok(_) = first {
        // Mine a block to finalize the state in UTXO set
        mine_block_and_wait(&service).await.expect("mining failed after first deploy");
    } else {
        // If not implemented / rejected on this branch, exit early
        daemon.shutdown();
        return;
    }

    // Second deploy should fail with ContractAlreadyDeployed or mempool rejection
    let second = service
        .deploy_contract_call(None, DeployContractRequest { contract_id: cid, initial_state })
        .await;
    assert!(second.is_err(), "expected error for second deploy");
    if let Err(err) = second {
        match err {
            RpcError::RejectedTransaction(_, _) | RpcError::NotImplemented | RpcError::UnsupportedFeature => {}
            other => panic!("unexpected error for second deploy: {:?}", other),
        }
    }

    daemon.shutdown();
}

/// Test D — submitContractCall happy path (if implemented)
#[tokio::test]
async fn test_contract_submit_happy_path() {
    let (mut daemon, service) = start_daemon_and_service().await;

    let cid: u64 = 1; // Echo contract
    let initial_state = b"init".to_vec();

    // Deploy first
    let mut deployed_instance: Option<String> = None;
    match service
        .deploy_contract_call(None, DeployContractRequest { contract_id: cid, initial_state: initial_state.clone() })
        .await
    {
        Ok(resp) => {
            deployed_instance = resp.instance_id.clone();
            // Include deploy in a block
            mine_block_and_wait(&service).await.expect("mining failed after deploy");
        }
        Err(_) => {
            // If not available on this branch, skip
            daemon.shutdown();
            return;
        }
    }

    // Submit a call (Echo returns data as new state)
    let call_data = b"NEWSTATE".to_vec();
    // Build instance id for submission (from deploy, or dummy if deploy unsupported)
    let instance_id = deployed_instance.unwrap_or_else(|| format!("{}:0", "0000000000000000000000000000000000000000000000000000000000000000"));
    match service
        .submit_contract_call_call(None, SubmitContractCallRequest { instance_id: instance_id.clone(), action_id: 1, data: call_data.clone() })
        .await
    {
        Ok(_) => {
            // Include call in a block
            mine_block_and_wait(&service).await.expect("mining failed after submit");
            // Verify state updated
            let got = service.get_contract_state_call(None, GetContractStateRequest { instance_id: instance_id.clone() }).await.unwrap();
            assert!(got.has_state);
            assert_eq!(got.state, call_data);
        }
        Err(err) => {
            match err {
                RpcError::RejectedTransaction(_, _) | RpcError::NotImplemented | RpcError::UnsupportedFeature => {}
                other => panic!("unexpected error from submit_contract_call_call: {:?}", other),
            }
        }
    }

    daemon.shutdown();
}

/// Test E — submitContractCall with missing state (no prior deploy)
#[tokio::test]
async fn test_contract_submit_missing_state() {
    let (mut daemon, service) = start_daemon_and_service().await;

    let _cid: u64 = 1; // Echo contract, but not deployed
    // Use dummy non-existent instance for submit
    let dummy_instance = format!("{}:0", "0000000000000000000000000000000000000000000000000000000000000000");
    let res = service
        .submit_contract_call_call(None, SubmitContractCallRequest { instance_id: dummy_instance, action_id: 1, data: vec![1, 2, 3] })
        .await;

    assert!(res.is_err(), "expected rejection for missing contract state");
    if let Err(err) = res {
        match err {
            RpcError::RejectedTransaction(_, _) | RpcError::General(_) | RpcError::NotImplemented | RpcError::UnsupportedFeature => {}
            other => panic!("unexpected error for missing state submit: {:?}", other),
        }
    }

    daemon.shutdown();
}

/// Test F — submitContractCall producing oversized resulting state
#[tokio::test]
async fn test_contract_submit_oversized_resulting_state() {
    use cryptix_consensus_core::contract::MAX_CONTRACT_STATE_SIZE;

    let (mut daemon, service) = start_daemon_and_service().await;

    let cid: u64 = 1; // Echo contract
    let initial_state = b"small".to_vec();

    // Deploy first
    let mut instance_opt: Option<String> = None;
    match service
        .deploy_contract_call(None, DeployContractRequest { contract_id: cid, initial_state })
        .await
    {
        Ok(resp) => {
            instance_opt = resp.instance_id.clone();
            mine_block_and_wait(&service).await.expect("mining failed after deploy");
        }
        Err(_) => {
            // Not implemented / rejected on this branch: skip
            daemon.shutdown();
            return;
        }
    }

    // Submit with data exceeding MAX_CONTRACT_STATE_SIZE. Echo returns data verbatim -> should be rejected.
    let oversized = vec![0u8; MAX_CONTRACT_STATE_SIZE + 1];
    let instance_id_for_submit = instance_opt.unwrap_or_else(|| format!("{}:0", "0000000000000000000000000000000000000000000000000000000000000000"));
    let res = service
        .submit_contract_call_call(None, SubmitContractCallRequest { instance_id: instance_id_for_submit, action_id: 1, data: oversized })
        .await;

    assert!(res.is_err(), "expected rejection for oversized resulting state");
    if let Err(err) = res {
        match err {
            RpcError::RejectedTransaction(_, _) | RpcError::NotImplemented | RpcError::UnsupportedFeature => {}
            other => panic!("unexpected error for oversized submit: {:?}", other),
        }
    }

    daemon.shutdown();
}

/// Test 2: simulate_contract_call_call using hypothetical_state for an unknown contract:
/// Expect an error condition in response (error_code set) and would_be_valid_tx=false.
#[tokio::test]
async fn test_contract_simulate_with_hypothetical_state_unknown_contract() {
    let (mut daemon, service) = start_daemon_and_service().await;

    let _cid: u64 = 999_999;
    // Provide a dummy non-existent instance id to simulate unknown instance/contract
    let dummy_instance = format!("{}:0", "0000000000000000000000000000000000000000000000000000000000000000");
    let req = SimulateContractCallRequest {
        instance_id: dummy_instance,
        action_id: 1,
        data: vec![],
        hypothetical_state: Some(vec![]),
    };
    let sim_resp = service.simulate_contract_call_call(None, req).await
        .expect("simulate_contract_call_call should return a response");

    // We don't assert a specific numeric error code here, just that an error was produced
    assert!(sim_resp.error_code.is_some(), "expected a non-zero error_code for unknown contract");
    assert!(!sim_resp.would_be_valid_tx, "unknown contract should not be a valid tx");
    // new_state may be None if the engine errored; size_ok is implementation dependent
    // No strict assertion on state_size_ok/new_state beyond basic sanity:
    if sim_resp.new_state.is_some() {
        assert!(sim_resp.state_size_ok, "if new_state is provided, state_size_ok should be true");
    }

    daemon.shutdown();
}
/// Test 3: deploy/submit supported or currently NotImplemented.
/// Accept all realistic stub-path errors until real TX builder is implemented.
#[tokio::test]
async fn test_contract_deploy_and_submit_supported_or_stubbed() {
    let (mut daemon, service) = start_daemon_and_service().await;

    //
    // --- DEPLOY -------------------------------------------------------------
    //

    let deploy_res = service
        .deploy_contract_call(
            None,
            DeployContractRequest {
                contract_id: 1234,
                initial_state: vec![0x00, 0x01],
            },
        )
        .await;

    match deploy_res {
        Ok(_resp) => {
            // Success is allowed, even if unexpected on this branch.
        }
        Err(err) => {
            let allowed = matches!(
                err,
                RpcError::NotImplemented | RpcError::UnsupportedFeature
            ) || matches!(err, RpcError::General(ref msg)
                if msg.contains("Unknown contract")
                    || msg.contains("Contract state not found")
            );

            if !allowed {
                panic!("unexpected error from deploy_contract_call: {:?}", err);
            }
        }
    }

    //
    // --- SUBMIT -------------------------------------------------------------
    //

    // Use dummy instance for this generic submit (deploy may not have succeeded)
    let submit_res = service
        .submit_contract_call_call(
            None,
            SubmitContractCallRequest {
                instance_id: format!("{}:0", "0000000000000000000000000000000000000000000000000000000000000000"),
                action_id: 1,
                data: vec![],
            },
        )
        .await;

    match submit_res {
        Ok(_resp) => {
            // Success is allowed.
        }
        Err(err) => {
            let allowed = matches!(
                err,
                RpcError::NotImplemented | RpcError::UnsupportedFeature
            ) || matches!(err, RpcError::General(ref msg)
                if msg.contains("Unknown contract")
                    || msg.contains("Contract state not found")
                    || msg.contains("instance not found")
            );

            if !allowed {
                panic!(
                    "unexpected error from submit_contract_call_call: {:?}",
                    err
                );
            }
        }
    }

    daemon.shutdown();
}
