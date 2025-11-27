use clap::{ArgAction, Parser, ValueEnum};
use cryptix_addresses::Address;
use cryptix_grpc_client::GrpcClient;
use cryptix_rpc_core::api::rpc::RpcApi;
use cryptix_rpc_core::error::RpcResult;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use tokio::signal;
use tokio::task::JoinHandle;

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Algo {
    Sha3,
    Blake3,
}

#[derive(Parser, Debug)]
#[command(name = "token_miner", about = "CPU miner for Cryptix token mining contracts (IDs 250=SHA3, 251=BLAKE3).")]
struct Opts {
    /// Mining algorithm: sha3 or blake3
    #[arg(long, value_enum)]
    algo: Algo,

    /// Contract ID to mine (250 for SHA3 or 251 for BLAKE3)
    #[arg(long)]
    contract_id: u64,

    /// Instance ID "<txid>:<vout>" of the mining contract instance
    #[arg(long)]
    instance: String,

    /// Reward address (Bech32)
    #[arg(long)]
    reward_address: String,

    /// gRPC endpoint (default grpc://127.0.0.1:19201). Fully overrideable.
    #[arg(long, default_value = "grpc://127.0.0.1:19201")]
    endpoint: String,

    /// Number of worker threads. Defaults to number_of_cpus.
    #[arg(long)]
    threads: Option<usize>,

    /// Submit attempts even if local PoW precheck fails difficulty (not recommended)
    #[arg(long, action=ArgAction::SetTrue)]
    submit_blind: bool,

    /// Verbose logging
    #[arg(long, action=ArgAction::SetTrue)]
    verbose: bool,
}

#[derive(Clone, Copy, Debug)]
struct DifficultyInfo {
    paused: bool,
    difficulty_bits: u8,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();

    if opts.contract_id != 250 && opts.contract_id != 251 {
        anyhow::bail!(
            "Unsupported contract_id: {}. Use 250 (SHA3) or 251 (BLAKE3).",
            opts.contract_id
        );
    }
    if matches!(opts.algo, Algo::Sha3) && opts.contract_id != 250 {
        eprintln!("Warning: algo sha3 is typically used with contract 250");
    }
    if matches!(opts.algo, Algo::Blake3) && opts.contract_id != 251 {
        eprintln!("Warning: algo blake3 is typically used with contract 251");
    }

    // Parse reward identity: prefer Bech32 Address; if it fails, try raw hex-32
    let mut miner_hash = [0u8; 32];
    match Address::try_from(opts.reward_address.as_str()) {
        Ok(addr) => {
            // Use payload directly if it happens to parse; otherwise we'll fallback
            let payload_len = addr.payload.len();
            if payload_len == 32 {
                miner_hash.copy_from_slice(&addr.payload);
            } else {
                eprintln!("Warning: parsed Bech32 payload length {} != 32, deriving miner hash from string.", payload_len);
                let h = blake3::hash(opts.reward_address.as_bytes());
                miner_hash.copy_from_slice(h.as_bytes());
            }
        }
        Err(_) => {
            // No validation: try hex-32; if that fails, derive a 32-byte id from the raw string
            let mut s = opts.reward_address.trim().to_string();
            if let Some(stripped) = s.strip_prefix("0x") {
                s = stripped.to_string();
            }
            match hex::decode(&s) {
                Ok(bytes) if bytes.len() == 32 => {
                    miner_hash.copy_from_slice(&bytes);
                    eprintln!("Warning: using raw hex-32 as miner identity (no address validation).");
                }
                _ => {
                    // Last resort: deterministic 32-byte id from the input string (no validation)
                    let h = blake3::hash(opts.reward_address.as_bytes());
                    miner_hash.copy_from_slice(h.as_bytes());
                    eprintln!("Warning: reward-address not parsed; using blake3(input) as miner identity (no address validation).");
                }
            }
        }
    }

    // Connect gRPC
    let client = Arc::new(
        GrpcClient::connect(opts.endpoint.clone())
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()))?,
    );
    if opts.verbose {
        println!("Connected to {}", opts.endpoint);
    }

    // Control flags and stats
    let threads = opts.threads.unwrap_or_else(num_cpus::get);
    let stop = Arc::new(AtomicBool::new(false));
    let submit_inflight = Arc::new(AtomicBool::new(false));
    let total_hashes = Arc::new(AtomicU64::new(0));
    let last_report = Arc::new(AtomicU64::new(now_millis()));

    // CTRL+C handler
    {
        let stop = stop.clone();
        tokio::spawn(async move {
            let _ = signal::ctrl_c().await;
            eprintln!("CTRL+C received, stopping...");
            stop.store(true, Ordering::SeqCst);
        });
    }

    // Difficulty polling loop (every 3s)
    let diff_info = Arc::new(tokio::sync::RwLock::new(DifficultyInfo {
        paused: false,
        difficulty_bits: 1,
    }));
    {
        let client = client.clone();
        let diff_info = diff_info.clone();
        let inst = opts.instance.clone();
        tokio::spawn(async move {
            loop {
                match get_miner_difficulty(&*client, &inst).await {
                    Ok(info) => {
                        let mut w = diff_info.write().await;
                        *w = info;
                    }
                    Err(e) => {
                        eprintln!("diff poll error: {}", e.to_string());
                    }
                }
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        });
    }

    // Spawn workers
    let mut handles: Vec<JoinHandle<()>> = Vec::with_capacity(threads);
    for t in 0..threads {
        let client = client.clone();
        let miner_hash = miner_hash;
        let stop = stop.clone();
        let submit_inflight = submit_inflight.clone();
        let total_hashes = total_hashes.clone();
        let last_report = last_report.clone();
        let diff_info = diff_info.clone();
        let algo = opts.algo;
        let cid = opts.contract_id;
        let verbose = opts.verbose;
        let submit_blind = opts.submit_blind;
        let inst = opts.instance.clone();

        let start_nonce = (t as u64) << 32;
        handles.push(tokio::spawn(async move {
            if verbose {
                println!("[worker {}] start_nonce={}", t, start_nonce);
            }
            // Worker nonce space: disjoint strides over u64
            let mut nonce: u64 = start_nonce;
            let mut local = 0u64;
            let mut last_tick = Instant::now();

            while !stop.load(Ordering::SeqCst) {
                // Stats
                local += 1;
                if last_tick.elapsed() >= Duration::from_millis(250) {
                    total_hashes.fetch_add(local, Ordering::Relaxed);
                    local = 0;
                    last_tick = Instant::now();

                    let lr = last_report.load(Ordering::Relaxed);
                    if now_millis() - lr >= 2000 {
                        // one worker prints stats
                        if last_report
                            .compare_exchange(lr, now_millis(), Ordering::SeqCst, Ordering::SeqCst)
                            .is_ok()
                        {
                            let total = total_hashes.swap(0, Ordering::Relaxed);
                            let hps = (total as f64) / 2.0;
                            println!("hashrate ~{:.0} H/s", hps);
                        }
                    }
                }

                // Snapshot difficulty
                let snap = {
                    let r = diff_info.read().await;
                    *r
                };
                if snap.paused {
                    // backoff while paused
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    continue;
                }

                // Pre-hash locally using the same preimage rule as the contract:
                // preimage = "CXMIN_" + "SHA3"/"BLK3" + contract_id(be) + block_height(be=0) + miner(32) + nonce(be)
                // Then check leading zeros >= difficulty_bits
                let ok = if submit_blind {
                    true
                } else {
                    match algo {
                        Algo::Sha3 => precheck_sha3(cid, &miner_hash, nonce, snap.difficulty_bits),
                        Algo::Blake3 => precheck_blake3(cid, &miner_hash, nonce, snap.difficulty_bits),
                    }
                };

                if ok {
                    // prevent concurrent submits flooding
                    if submit_inflight
                        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                        .is_err()
                    {
                        // another submit in flight, skip this nonce
                        nonce = nonce.wrapping_add(threads as u64);
                        continue;
                    }

                    // Action 1 data format: miner_hash (32) + nonce (u64 LE)
                    let mut data = Vec::with_capacity(32 + 8);
                    data.extend_from_slice(&miner_hash);
                    data.extend_from_slice(&nonce.to_le_bytes());

                    let client_ref = client.clone();
                    let submit_inflight_ref = submit_inflight.clone();
                    let inst2 = inst.clone();
                    // Submit async (don't block the loop)
                    tokio::spawn(async move {
                        let res: RpcResult<_> =
                            client_ref.submit_contract_call(inst2, 1, data).await;
                        match res {
                            Ok(resp) => {
                                println!("Submitted tx {}", resp.transaction_id);
                            }
                            Err(e) => {
                                eprintln!("Submit error: {}", e.to_string());
                            }
                        }
                        submit_inflight_ref.store(false, Ordering::SeqCst);
                    });
                }

                // Next nonce
                nonce = nonce.wrapping_add(threads as u64);
            }
        }));
    }

    // Wait for workers
    for h in handles {
        let _ = h.await;
    }
    println!("Stopped.");
    Ok(())
}

// Poll difficulty by reading contract state and parsing CxMinState encoding
async fn get_miner_difficulty(client: &GrpcClient, instance_id: &str) -> anyhow::Result<DifficultyInfo> {
    // Use GetContractState (gRPC wired) to get raw state
    let resp = client
        .get_contract_state(instance_id.to_string())
        .await
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    if !resp.has_state {
        // Not yet deployed
        return Ok(DifficultyInfo {
            paused: false,
            difficulty_bits: 1,
        });
    }
    let mut p = &resp.state[..];

    // Decode sequence as per CxMinState::encode
    // admin:32
    if p.len() < 32 {
        anyhow::bail!("state too small");
    }
    p = &p[32..];
    // paused:1
    if p.is_empty() {
        anyhow::bail!("state too small");
    }
    let paused = p[0] != 0;
    p = &p[1..];
    // total_supply:8
    if p.len() < 8 {
        anyhow::bail!("state too small");
    }
    p = &p[8..];
    // max_supply:8
    if p.len() < 8 {
        anyhow::bail!("state too small");
    }
    p = &p[8..];
    // reward_per_block:8
    if p.len() < 8 {
        anyhow::bail!("state too small");
    }
    p = &p[8..];
    // initial_reward_per_block:8
    if p.len() < 8 {
        anyhow::bail!("state too small");
    }
    p = &p[8..];
    // deflation_ppm:4
    if p.len() < 4 {
        anyhow::bail!("state too small");
    }
    p = &p[4..];
    // last_deflation_height:8
    if p.len() < 8 {
        anyhow::bail!("state too small");
    }
    p = &p[8..];
    // difficulty_bits:1
    if p.is_empty() {
        anyhow::bail!("state too small");
    }
    let difficulty_bits = p[0];

    // Note: We don't need to read further fields (target_interval_blocks, last_reward_height, 
    // blocks_mined, balances, metatags, or decimals) as we only need difficulty_bits for mining

    Ok(DifficultyInfo {
        paused,
        difficulty_bits,
    })
}

// Leading zero count on 32-byte digest
fn leading_zeros_256(h: &[u8; 32]) -> u32 {
    let mut total: u32 = 0;
    for b in h {
        if *b == 0 {
            total += 8;
        } else {
            total += b.leading_zeros();
            break;
        }
    }
    total
}

fn preimage_bytes(prefix_algo: &str, contract_id: u64, miner: &[u8; 32], nonce: u64) -> Vec<u8> {
    // "CXMIN_" + prefix_algo + contract_id(be) + block_height(be=0) + miner + nonce(be)
    // Note: Using block_height instead of block_time as per the updated contract
    let mut v = Vec::with_capacity(6 + 4 + 8 + 8 + 32 + 8);
    v.extend_from_slice(b"CXMIN_");
    v.extend_from_slice(prefix_algo.as_bytes());
    v.extend_from_slice(&contract_id.to_be_bytes());
    v.extend_from_slice(&0u64.to_be_bytes()); // block_height (0 for local precheck)
    v.extend_from_slice(miner);
    v.extend_from_slice(&nonce.to_be_bytes());
    v
}

fn precheck_sha3(contract_id: u64, miner: &[u8; 32], nonce: u64, difficulty_bits: u8) -> bool {
    use sha3::{Digest, Sha3_256};
    let pre = preimage_bytes("SHA3", contract_id, miner, nonce);
    let mut hasher = Sha3_256::new();
    hasher.update(pre);
    let out = hasher.finalize();
    let mut h = [0u8; 32];
    h.copy_from_slice(&out[..]);
    leading_zeros_256(&h) >= difficulty_bits as u32
}

fn precheck_blake3(contract_id: u64, miner: &[u8; 32], nonce: u64, difficulty_bits: u8) -> bool {
    let pre = preimage_bytes("BLK3", contract_id, miner, nonce);
    let mut hasher = blake3::Hasher::new();
    hasher.update(&pre);
    let out = hasher.finalize();
    let mut h = [0u8; 32];
    h.copy_from_slice(out.as_bytes());
    leading_zeros_256(&h) >= difficulty_bits as u32
}

#[inline]
fn now_millis() -> u64 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
