use cryptix_grpc_client::GrpcClient;
use cryptix_rpc_core::api::rpc::RpcApi;
use cryptix_rpc_core::notify::mode::NotificationMode;
use cryptix_utils_tower::counters::TowerConnectionCounters;
use std::process::ExitCode;
use std::sync::Arc;

#[tokio::main]
async fn main() -> ExitCode {
    let endpoint = std::env::args().nth(1).unwrap_or_else(|| "grpc://127.0.0.1:19201".to_string());
    match run(endpoint).await {
        Ok(_) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("check_grpc_bootstrap failed: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn run(endpoint: String) -> Result<(), Box<dyn std::error::Error>> {
    let client = GrpcClient::connect_with_args(
        NotificationMode::Direct,
        endpoint.clone(),
        None,
        false,
        None,
        false,
        Some(30_000),
        Arc::new(TowerConnectionCounters::default()),
    )
    .await?;
    println!("connected: {endpoint}");

    let server = client.get_server_info().await?;
    println!(
        "server_info: version={}, network_id={}, synced={}, utxo_index={}",
        server.server_version, server.network_id, server.is_synced, server.has_utxo_index
    );

    match client.get_block_dag_info().await {
        Ok(info) => {
            println!(
                "block_dag_info: blocks={}, headers={}, sink={}, virtual_daa_score={}",
                info.block_count, info.header_count, info.sink, info.virtual_daa_score
            );
        }
        Err(err) => {
            println!("block_dag_info_error: {err}");
        }
    }

    match client.get_token_health().await {
        Ok(h) => {
            println!(
                "token_health: state={}, degraded={}, bootstrap_in_progress={}, live_correct={}, last_applied_block={:?}, last_sequence={}",
                h.token_state, h.is_degraded, h.bootstrap_in_progress, h.live_correct, h.last_applied_block, h.last_sequence
            );
        }
        Err(err) => {
            println!("token_health_error: {err}");
        }
    }

    match client.get_sc_bootstrap_sources().await {
        Ok(resp) => {
            println!("sc_bootstrap_sources_count: {}", resp.sources.len());
            if let Some(head) = resp.sources.first() {
                println!(
                    "sc_bootstrap_sources_first: snapshot_id={}, protocol_version={}, network_id={}, node_identity={}, at_block_hash={}, at_daa_score={}, state_hash_at_fp={}",
                    head.snapshot_id,
                    head.protocol_version,
                    head.network_id,
                    head.node_identity,
                    head.at_block_hash,
                    head.at_daa_score,
                    head.state_hash_at_fp
                );
            }
        }
        Err(err) => {
            println!("sc_bootstrap_sources_error: {err}");
        }
    }

    match client.get_sc_snapshot_head().await {
        Ok(resp) => match resp.head {
            Some(head) => {
                println!(
                    "sc_snapshot_head: snapshot_id={}, protocol_version={}, network_id={}, node_identity={}, at_block_hash={}, at_daa_score={}, state_hash_at_fp={}",
                    head.snapshot_id,
                    head.protocol_version,
                    head.network_id,
                    head.node_identity,
                    head.at_block_hash,
                    head.at_daa_score,
                    head.state_hash_at_fp
                );
            }
            None => {
                println!("sc_snapshot_head: none");
            }
        },
        Err(err) => {
            println!("sc_snapshot_head_error: {err}");
        }
    }

    client.disconnect().await?;
    Ok(())
}
