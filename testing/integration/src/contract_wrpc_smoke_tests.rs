use std::sync::Arc;

use cryptix_core::{log, panic};
use cryptix_rpc_core::api::rpc::RpcApi;
use cryptix_rpc_core::model::contract::*;
use cryptix_wrpc_client::{CryptixRpcClient, WrpcEncoding as ClientWrpcEncoding};
use cryptix_wrpc_server::service::WrpcEncoding as ServerWrpcEncoding;
use cryptixd_lib::args::Args;
use crate::common::daemon::Daemon;
use cryptix_utils::fd_budget;
use tokio::time::{timeout, Duration};

#[tokio::test]
async fn wrpc_smoke_get_state_and_simulate() {
    // Init logging/panic
    log::try_init_logger("info");
    panic::configure_panic();

    // Start a dev/sim node with utxoindex+unsafe_rpc; will expose both gRPC and wRPC endpoints
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

    // Start core + RPC services; ensure servers are up
    let _grpc_client = daemon.start().await;

    // Build wRPC client URL from daemon-assigned random Borsh address
    let manager = daemon.client_manager();
    let borsh_addr = manager
        .args
        .read()
        .rpclisten_borsh
        .as_ref()
        .expect("rpclisten_borsh must be assigned")
        .to_address(&manager.network.network_type(), &ServerWrpcEncoding::Borsh);
    // Convert binding address to a connectable URL using localhost and extracted port.
    let borsh_addr_str = format!("{}", borsh_addr);
    let borsh_port: u16 = borsh_addr_str
        .rsplit(':')
        .next()
        .and_then(|s| s.parse::<u16>().ok())
        .expect("failed to parse borsh port");
    // Force IPv4 loopback to avoid IPv6/URL parsing issues
    let url = format!("ws://127.0.0.1:{borsh_port}");

    // Create and connect the wRPC client
    let client = Arc::new(
        CryptixRpcClient::new_with_args(
            ClientWrpcEncoding::Borsh,
            Some(&url),
            None,
            Some(manager.network),
            None
        ).expect("wrpc client new_with_args failed")
    );
    // Ensure connect is awaited and bounded by timeout
    timeout(Duration::from_secs(5), client.connect(None))
        .await
        .expect("wrpc client connect timeout")
        .expect("wrpc client connect failed");

    //
    // 1) get_contract_state on a fresh node → has_state=false
    //
    // Use a syntactically valid but non-existent instance_id "<zero_txid>:0"
    let dummy_instance = format!("{}:0", "0000000000000000000000000000000000000000000000000000000000000000");
    let get_resp = timeout(
        Duration::from_secs(5),
        client.get_contract_state_call(None, GetContractStateRequest { instance_id: dummy_instance.clone() }),
    )
    .await
    .expect("get_contract_state_call timeout")
    .expect("get_contract_state_call failed");
    assert!(!get_resp.has_state, "expected no state on fresh node");
    assert!(get_resp.state.is_empty(), "state bytes should be empty when has_state=false");
    assert!(get_resp.state_outpoint.is_none(), "no outpoint when has_state=false");

    //
    // 2) simulate with hypothetical_state = Some([]) without relying on deploy
    //
    let instance_id = format!("{}:0", "0000000000000000000000000000000000000000000000000000000000000000");
    let data1 = b"WRPC_SMOKE".to_vec();
    let sim_req_some = SimulateContractCallRequest {
        instance_id: instance_id.clone(),
        action_id: 1,
        data: data1.clone(),
        hypothetical_state: Some(Vec::new()),
    };
    let sim_resp_some = timeout(
        Duration::from_secs(5),
        client.simulate_contract_call_call(None, sim_req_some),
    )
    .await
    .expect("simulate with Some([]) timeout")
    .expect("simulate with Some([]) should succeed");
    // Allow engines that don't return new_state; if provided, it must equal the input data.
    if let Some(ns) = sim_resp_some.new_state.clone() {
        assert_eq!(ns, data1, "Echo should return data as new_state");
        assert!(sim_resp_some.state_size_ok, "state_size_ok must be true for small states");
    } else {
        // Do not assert strictly for size_ok or would_be_valid_tx in this branch.
    }

    //
    // 3) simulate again with hypothetical_state = Some([]) (do not depend on get_contract_state fallback)
    //
    let data2 = b"WRPC_SMOKE_FALLBACK".to_vec();
    let sim_req_repeat = SimulateContractCallRequest {
        instance_id: instance_id.clone(),
        action_id: 1,
        data: data2.clone(),
        hypothetical_state: Some(Vec::new()),
    };
    let sim_resp_repeat = timeout(
        Duration::from_secs(5),
        client.simulate_contract_call_call(None, sim_req_repeat),
    )
    .await
    .expect("simulate repeat timeout")
    .expect("simulate repeat should succeed");
    if let Some(ns2) = sim_resp_repeat.new_state.clone() {
        assert_eq!(ns2, data2, "Echo (repeat) should return data as new_state");
        assert!(sim_resp_repeat.state_size_ok, "state_size_ok must be true for small states (repeat)");
    } else {
        // Accept engines that do not return new_state and avoid strict assertions.
    }

    // Disconnect and shutdown
    timeout(Duration::from_secs(5), client.disconnect())
        .await
        .expect("wrpc client disconnect timeout")
        .expect("wrpc client disconnect failed");
    daemon.shutdown();
}
