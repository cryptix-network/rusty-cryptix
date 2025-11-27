use std::sync::Arc;

use cryptix_core::{log, panic};
use cryptix_rpc_core::api::rpc::RpcApi;
use cryptix_rpc_core::model::contract::*;
use cryptixd_lib::args::Args;
use crate::common::daemon::Daemon;
use cryptix_utils::fd_budget;

#[ignore]
#[tokio::test]
async fn grpc_smoke_get_state_and_simulate() {
    // Init logging/panic
    log::try_init_logger("info");
    panic::configure_panic();

    // Start a dev/sim node with utxoindex+unsafe_rpc and obtain a GrpcClient
    let args = Args {
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

    // Start core + RPC services and get a GrpcClient connected to grpc://localhost:<port>
    let client = daemon.start().await;

    //
    // 1) get_contract_state on a fresh node → has_state=false
    //
    // Use a syntactically valid but non-existent instance_id "<zero_txid>:0"
    let dummy_instance = format!("{}:0", "0000000000000000000000000000000000000000000000000000000000000000");
    let get_resp = client
        .get_contract_state_call(None, GetContractStateRequest { instance_id: dummy_instance.clone() })
        .await
        .expect("get_contract_state_call failed");
    assert!(!get_resp.has_state, "expected no state on fresh node");
    assert!(get_resp.state.is_empty(), "state bytes should be empty when has_state=false");
    assert!(get_resp.state_outpoint.is_none(), "no outpoint when has_state=false");

    //
    // Deploy Echo (cid=1) to obtain a valid instance_id for simulation
    //
    let echo_cid: u64 = 1; // Echo contract (hardcoded)
    let dep_resp = client
        .deploy_contract_call(None, DeployContractRequest { contract_id: echo_cid, initial_state: Vec::new() })
        .await
        .expect("deploy_contract_call failed");
    let instance_id = dep_resp.instance_id.expect("deploy should return instance_id");

    //
    // 2) simulate with hypothetical_state = Some([]) using Echo instance
    //
    let data1 = b"GRPC_SMOKE".to_vec();
    let sim_req_some = SimulateContractCallRequest {
        instance_id: instance_id.clone(),
        action_id: 1,
        data: data1.clone(),
        hypothetical_state: Some(Vec::new()),
    };
    let sim_resp_some = client
        .simulate_contract_call_call(None, sim_req_some)
        .await
        .expect("simulate_contract_call_call with Some([]) should succeed");
    assert_eq!(sim_resp_some.new_state, Some(data1), "Echo should return data as new_state");
    assert!(sim_resp_some.state_size_ok, "state_size_ok must be true for small states");
    assert!(sim_resp_some.would_be_valid_tx, "would_be_valid_tx must be true for Echo small state");

    //
    // 3) simulate with hypothetical_state = None (fallback to get_contract_state)
    //
    let data2 = b"GRPC_SMOKE_FALLBACK".to_vec();
    let sim_req_none = SimulateContractCallRequest {
        instance_id: instance_id.clone(),
        action_id: 1,
        data: data2.clone(),
        hypothetical_state: None,
    };
    let sim_resp_none = client
        .simulate_contract_call_call(None, sim_req_none)
        .await
        .expect("simulate_contract_call_call with None (fallback) should succeed");
    assert_eq!(sim_resp_none.new_state, Some(data2), "Echo (fallback) should return data as new_state");
    assert!(sim_resp_none.state_size_ok, "state_size_ok must be true for small states (fallback)");
    assert!(sim_resp_none.would_be_valid_tx, "would_be_valid_tx must be true for Echo small state (fallback)");

    // Fold-up
    client.disconnect().await.unwrap();
    daemon.shutdown();
}
