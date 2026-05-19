use cryptix_rpc_core::api::rpc::RpcApi;
use cryptix_wrpc_client::{
    client::{ConnectOptions, ConnectStrategy},
    prelude::{NetworkId, NetworkType},
    result::Result,
    CryptixRpcClient, WrpcEncoding,
};
use std::process::ExitCode;
use std::time::Duration;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(_) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("check_bootstrap failed: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let url = Some("ws://127.0.0.1:19301");
    let client = CryptixRpcClient::new(
        WrpcEncoding::Borsh,
        url,
        None,
        Some(NetworkId::new(NetworkType::Mainnet)),
        None,
    )?;

    let options = ConnectOptions {
        block_async_connect: true,
        connect_timeout: Some(Duration::from_secs(8)),
        strategy: ConnectStrategy::Fallback,
        ..Default::default()
    };
    client.connect(Some(options)).await?;

    let server = client.get_server_info().await?;
    println!(
        "server_info: version={}, network_id={}, synced={}, utxo_index={}",
        server.server_version, server.network_id, server.is_synced, server.has_utxo_index
    );

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
            for (idx, src) in resp.sources.iter().enumerate() {
                println!(
                    "source[{idx}]: snapshot_id={}, protocol_version={}, network_id={}, node_identity={}, at_block_hash={}, at_daa_score={}, state_hash_at_fp={}",
                    src.snapshot_id,
                    src.protocol_version,
                    src.network_id,
                    src.node_identity,
                    src.at_block_hash,
                    src.at_daa_score,
                    src.state_hash_at_fp
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
