use crate::helpers::{try_convert_option_to_token_address, option_string_to_display, ask_convert_address};
use crate::imports::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;
use crate::modules::token_transfer::secure_token_transfer;
use cryptix_consensus_core::Hash;

const SOMPI_PER_CRYPTIX: u64 = 100_000_000;

// Helper structs for token state decoding
#[derive(Debug)]
pub struct Cx20State {
    pub admin: [u8; 32],
    pub flags: u16,
    pub balances: Vec<([u8; 32], u64)>,
    pub symbol_hash: Option<[u8; 32]>,
    pub decimals: Option<u8>,
    pub freeze_set: Option<Vec<[u8; 32]>>,
    pub allowances: Option<Vec<Cx20Allowance>>,
}

#[derive(Debug)]
pub struct Cx20Allowance {
    pub owner: [u8; 32],
    pub spender: [u8; 32],
    pub amount: u64,
}

#[derive(Debug)]
pub struct Cx20MiniState {
    pub owner: [u8; 32],
    pub total_supply: u64,
    pub balances: Vec<([u8; 32], u64)>,
}

// CX-MIN mining token state
#[derive(Debug)]
pub struct CxMinState {
    pub admin: [u8; 32],
    pub paused: u8,
    pub total_supply: u64,
    pub max_supply: u64,
    pub reward_per_block: u64,
    pub initial_reward_per_block: u64,
    pub deflation_ppm: u32,
    pub last_deflation_height: u64,
    pub difficulty_bits: u8,
    pub target_interval_blocks: u64,
    pub last_reward_height: u64,
    pub blocks_mined: u64,
    pub balances: Vec<([u8; 32], u64)>,
    pub name: Vec<u8>,
    pub ticker: Vec<u8>,
    pub icon: Vec<u8>,
    pub decimals: u8, // 0 (whole tokens) if omitted, otherwise 1..=6
}

// Helper functions for state decoding
pub fn read_hash32(s: &[u8]) -> Result<([u8; 32], &[u8])> {
    if s.len() < 32 {
        return Err("Invalid state: not enough bytes for hash32".into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&s[..32]);
    Ok((out, &s[32..]))
}

pub fn read_u64_le(s: &[u8]) -> Result<(u64, &[u8])> {
    if s.len() < 8 {
        return Err("Invalid state: not enough bytes for u64".into());
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&s[..8]);
    Ok((u64::from_le_bytes(buf), &s[8..]))
}

pub fn read_u32_le(s: &[u8]) -> Result<(u32, &[u8])> {
    if s.len() < 4 {
        return Err("Invalid state: not enough bytes for u32".into());
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&s[..4]);
    Ok((u32::from_le_bytes(buf), &s[4..]))
}

pub fn read_u16_le(s: &[u8]) -> Result<(u16, &[u8])> {
    if s.len() < 2 {
        return Err("Invalid state: not enough bytes for u16".into());
    }
    let mut buf = [0u8; 2];
    buf.copy_from_slice(&s[..2]);
    Ok((u16::from_le_bytes(buf), &s[2..]))
}

pub fn read_u8(s: &[u8]) -> Result<(u8, &[u8])> {
    if s.is_empty() {
        return Err("Invalid state: not enough bytes for u8".into());
    }
    Ok((s[0], &s[1..]))
}

// CX20 Extended Token state decoder
pub fn decode_cx20_state(state: &[u8]) -> Result<Cx20State> {
    let mut s = state;
    
    // [admin:32][flags:2]
    let (admin, r1) = read_hash32(s)?; s = r1;
    let (flags, r2) = read_u16_le(s)?; s = r2;
    
    // balances: [n:2][n*(addr:32,amt:8)]
    let (n_bal, r3) = read_u16_le(s)?; s = r3;
    let mut balances = Vec::with_capacity(n_bal as usize);
    for _ in 0..n_bal {
        let (addr, r) = read_hash32(s)?; s = r;
        let (amt, r2) = read_u64_le(s)?; s = r2;
        balances.push((addr, amt));
    }
    
    // metadata (optional)
    let mut symbol_hash = None;
    let mut decimals = None;
    if (flags & 0b100) != 0 {
        let (sym, r) = read_hash32(s)?; s = r;
        symbol_hash = Some(sym);
        let (dec, r2) = read_u8(s)?; s = r2;
        decimals = Some(dec);
    }
    
    // freeze_set (optional): [nf:2][nf*addr32]
    let mut freeze_set = None;
    if (flags & 0b10) != 0 {
        let (nf, r) = read_u16_le(s)?; s = r;
        let mut fs = Vec::with_capacity(nf as usize);
        for _ in 0..nf {
            let (a, r2) = read_hash32(s)?; s = r2;
            fs.push(a);
        }
        freeze_set = Some(fs);
    }
    
    // allowances (optional): [na:2][na*(owner:32,spender:32,amt:8)]
    let mut allowances = None;
    if (flags & 0b1000) != 0 {
        let (na, r) = read_u16_le(s)?; s = r;
        let mut al = Vec::with_capacity(na as usize);
        for _ in 0..na {
            let (owner, r2) = read_hash32(s)?; s = r2;
            let (spender, r3) = read_hash32(s)?; s = r3;
            let (amt, r4) = read_u64_le(s)?; s = r4;
            al.push(Cx20Allowance { owner, spender, amount: amt });
        }
        allowances = Some(al);
    }
    
    Ok(Cx20State { 
        admin, 
        flags, 
        balances, 
        symbol_hash, 
        decimals, 
        freeze_set, 
        allowances 
    })
}

// CX20-MINI Token state decoder
pub fn decode_cx20_mini_state(state: &[u8]) -> Result<Cx20MiniState> {
    let mut s = state;
    
    // [owner:32][total_supply:8][n:2][n * ([addr:32][amt:8])]
    let (owner, r) = read_hash32(s)?; s = r;
    let (total_supply, r) = read_u64_le(s)?; s = r;
    let (n, r) = read_u16_le(s)?; s = r;
    
    let mut balances = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let (addr, r1) = read_hash32(s)?; s = r1;
        let (amt, r2) = read_u64_le(s)?; s = r2;
        balances.push((addr, amt));
    }
    
    Ok(Cx20MiniState { 
        owner, 
        total_supply, 
        balances 
    })
}

// CX-MIN mining token state decoder
pub fn decode_cx_min_state(state: &[u8]) -> Result<CxMinState> {
    let mut s = state;
    
    let (admin, r) = read_hash32(s)?; s = r;
    let (paused, r) = read_u8(s)?; s = r;

    let (total_supply, r) = read_u64_le(s)?; s = r;
    let (max_supply, r) = read_u64_le(s)?; s = r;
    let (reward_per_block, r) = read_u64_le(s)?; s = r;
    let (initial_reward_per_block, r) = read_u64_le(s)?; s = r;
    let (deflation_ppm, r) = read_u32_le(s)?; s = r;
    let (last_deflation_height, r) = read_u64_le(s)?; s = r;

    let (difficulty_bits, r) = read_u8(s)?; s = r;
    let (target_interval_blocks, r) = read_u64_le(s)?; s = r;
    let (last_reward_height, r) = read_u64_le(s)?; s = r;
    let (blocks_mined, r) = read_u64_le(s)?; s = r;

    let (n_bal, r) = read_u16_le(s)?; s = r;
    let mut balances = Vec::with_capacity(n_bal as usize);
    for _ in 0..n_bal {
        let (addr, r) = read_hash32(s)?; s = r;
        let (amt, r) = read_u64_le(s)?; s = r;
        if amt > 0 {
            balances.push((addr, amt));
        }
    }
    
    // Read metatags if present
    let mut name = Vec::new();
    let mut ticker = Vec::new();
    let mut icon = Vec::new();

    // If there's more data, try to read metatags
    if !s.is_empty() {
        // Read name length and data
        if s.len() >= 2 {
            let (name_len, r) = read_u16_le(s)?; s = r;
            if name_len > 0 && s.len() >= name_len as usize {
                name.extend_from_slice(&s[..name_len as usize]);
                s = &s[name_len as usize..];
            }
        }

        // Read ticker length and data
        if !s.is_empty() && s.len() >= 2 {
            let (ticker_len, r) = read_u16_le(s)?; s = r;
            if ticker_len > 0 && s.len() >= ticker_len as usize {
                ticker.extend_from_slice(&s[..ticker_len as usize]);
                s = &s[ticker_len as usize..];
            }
        }

        // Read icon length and data
        if !s.is_empty() && s.len() >= 2 {
            let (icon_len, r) = read_u16_le(s)?; s = r;
            if icon_len > 0 && s.len() >= icon_len as usize {
                icon.extend_from_slice(&s[..icon_len as usize]);
            }
        }
    }

    // Optional decimals at the very end. If absent => 0 (whole tokens)
    let mut decimals: u8 = 0;
    if !s.is_empty() {
        let (d, _r) = read_u8(s)?;
        decimals = d;
    }
    
    Ok(CxMinState {
        admin, paused,
        total_supply, max_supply, reward_per_block, initial_reward_per_block,
        deflation_ppm, last_deflation_height,
        difficulty_bits, target_interval_blocks, last_reward_height, blocks_mined,
        balances, name, ticker, icon, decimals
    })
}

// Helper methods for Cx20State
impl Cx20State {
    pub fn has_metadata(&self) -> bool { 
        (self.flags & 0b100) != 0 
    }
    
    pub fn has_freeze(&self) -> bool { 
        (self.flags & 0b10) != 0 
    }
    
    pub fn is_frozen(&self, addr: &[u8; 32]) -> bool {
        if !self.has_freeze() { 
            return false; 
        }
        
        if let Some(freeze_set) = &self.freeze_set {
            for frozen_addr in freeze_set {
                if frozen_addr == addr {
                    return true;
                }
            }
        }
        
        false
    }
}

// Get balance for an address from CX20 state
pub fn get_cx20_balance(state: &Cx20State, addr: &[u8; 32]) -> u64 {
    for (balance_addr, amount) in &state.balances {
        if balance_addr == addr {
            return *amount;
        }
    }
    0
}

// Get balance for an address from CX20-MINI state
pub fn get_cx20_mini_balance(state: &Cx20MiniState, addr: &[u8; 32]) -> u64 {
    for (balance_addr, amount) in &state.balances {
        if balance_addr == addr {
            return *amount;
        }
    }
    0
}

// Helpers for decimals formatting/parsing (no floats)
fn format_amount_with_decimals(amount: u64, decimals: u8) -> String {
    if decimals == 0 {
        return amount.to_string();
    }
    let d = decimals as usize;
    let scale = 10u64.pow(decimals as u32);
    let int_part = amount / scale;
    let frac_part = amount % scale;
    if frac_part == 0 {
        format!("{}", int_part)
    } else {
        // pad fractional part with leading zeros to length d, then trim trailing zeros
        let mut frac = format!("{:0width$}", frac_part, width = d);
        while frac.ends_with('0') {
            frac.pop();
        }
        format!("{}.{}", int_part, frac)
    }
}

fn parse_amount_with_decimals(input: &str, decimals: u8) -> Result<u64> {
    if decimals == 0 {
        return input.parse::<u64>().map_err(|_| -> crate::error::Error { "Invalid integer amount".into() });
    }
    let parts: Vec<&str> = input.split('.').collect();
    if parts.len() > 2 {
        return Err("Invalid amount format".into());
    }
    let int_str = parts[0];
    let frac_str = if parts.len() == 2 { parts[1] } else { "" };
    if frac_str.len() > decimals as usize {
        return Err(format!("Too many fractional digits (max {})", decimals).into());
    }
    let int_val = if int_str.is_empty() { 0 } else { int_str.parse::<u64>().map_err(|_| -> crate::error::Error { "Invalid integer part".into() })? };
    let mut frac_val: u64 = 0;
    if !frac_str.is_empty() {
        let mut s = frac_str.to_string();
        while s.len() < decimals as usize { s.push('0'); }
        frac_val = s.parse::<u64>().map_err(|_| -> crate::error::Error { "Invalid fractional part".into() })?;
    }
    let scale = 10u64.pow(decimals as u32);
    int_val.checked_mul(scale).and_then(|v| v.checked_add(frac_val)).ok_or_else(|| -> crate::error::Error { "Amount overflow".into() })
}

// Get balance for an address from CX-MIN state
pub fn get_cx_min_balance(state: &CxMinState, addr: &[u8; 32]) -> u64 {
    for (balance_addr, amount) in &state.balances {
        if balance_addr == addr {
            return *amount;
        }
    }
    0
}

// Mining helper functions
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
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

// Helper struct for mining difficulty
#[derive(Clone, Copy, Debug)]
struct DifficultyInfo {
    paused: bool,
    difficulty_bits: u8,
}

// Poll difficulty by reading contract state and parsing CxMinState encoding
async fn get_miner_difficulty(rpc: &Arc<DynRpcApi>, instance_id: &str) -> Result<DifficultyInfo> {
    // Use GetContractState to get raw state
    let resp = rpc.get_contract_state(instance_id.to_string()).await?;
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
        return Err("state too small".into());
    }
    p = &p[32..];
    // paused:1
    if p.is_empty() {
        return Err("state too small".into());
    }
    let paused = p[0] != 0;
    p = &p[1..];
    // total_supply:8
    if p.len() < 8 {
        return Err("state too small".into());
    }
    p = &p[8..];
    // max_supply:8
    if p.len() < 8 {
        return Err("state too small".into());
    }
    p = &p[8..];
    // reward_per_block:8
    if p.len() < 8 {
        return Err("state too small".into());
    }
    p = &p[8..];
    // initial_reward_per_block:8
    if p.len() < 8 {
        return Err("state too small".into());
    }
    p = &p[8..];
    // deflation_ppm:4
    if p.len() < 4 {
        return Err("state too small".into());
    }
    p = &p[4..];
    // last_deflation_height:8
    if p.len() < 8 {
        return Err("state too small".into());
    }
    p = &p[8..];
    // difficulty_bits:1
    if p.is_empty() {
        return Err("state too small".into());
    }
    let difficulty_bits = p[0];

    Ok(DifficultyInfo {
        paused,
        difficulty_bits,
    })
}

#[derive(Default, Handler)]
#[help("Token management operations")]
pub struct Token;

impl Token {
    async fn main(self: Arc<Self>, ctx: &Arc<dyn Context>, argv: Vec<String>, _cmd: &str) -> Result<()> {
        let ctx = ctx.clone().downcast_arc::<CryptixCli>()?;

        if argv.is_empty() {
            return self.display_help(ctx, argv).await;
        }

        match argv[0].as_str() {
            "balance" => self.balance(ctx, argv[1..].to_vec()).await,
            "send" => self.send(ctx, argv[1..].to_vec()).await,
            "deploy" => self.deploy(ctx, argv[1..].to_vec()).await,
            "list" => self.list(ctx, argv[1..].to_vec()).await,
            "info" => self.info(ctx, argv[1..].to_vec()).await,
            "mine" => self.mine(ctx, argv[1..].to_vec()).await,
            _ => {
                tprintln!(ctx, "Unknown token command: {}", argv[0]);
                self.display_help(ctx, argv).await
            }
        }
    }

    async fn display_help(self: Arc<Self>, ctx: Arc<CryptixCli>, _argv: Vec<String>) -> Result<()> {
        ctx.term().help(
            &[
                ("balance", "Check token balance for an address"),
                ("send", "Send tokens to another address"),
                ("deploy", "Deploy a new token contract"),
                ("list", "List all token contracts"),
                ("info", "Show detailed information about a token contract"),
                ("mine", "Mine tokens using a mining contract (SHA3=250, BLAKE3=251)"),
            ],
            Some("Usage: token <command> [options]"),
        )?;

        Ok(())
    }

    async fn balance(self: Arc<Self>, ctx: Arc<CryptixCli>, argv: Vec<String>) -> Result<()> {
        let mut instance_id: Option<String> = None;
        let mut address: Option<String> = None;
        let mut contract_id: Option<u64> = None;

        let mut i = 0;
        while i < argv.len() {
            match argv[i].as_str() {
                "--instance" => {
                    if i + 1 < argv.len() {
                        instance_id = Some(argv[i + 1].clone());
                        i += 2;
                    } else {
                        return Err("Missing instance ID".into());
                    }
                }
                "--address" => {
                    if i + 1 < argv.len() {
                        address = Some(argv[i + 1].clone());
                        i += 2;
                    } else {
                        return Err("Missing address".into());
                    }
                }
                "--contract" => {
                    if i + 1 < argv.len() {
                        contract_id = Some(argv[i + 1].parse::<u64>().map_err(|_| "Invalid contract ID")?);
                        i += 2;
                    } else {
                        return Err("Missing contract ID".into());
                    }
                }
                _ => {
                    return Err(format!("Unknown argument: {}", argv[i]).into());
                }
            }
        }

        let instance_id = instance_id.ok_or("Instance ID is required")?;
        // Try to convert the address to a token address hash
        let address_hash = match try_convert_option_to_token_address(&address) {
            Ok(hash) => hash,
            Err(e) => {
                // If it's not a valid hex address, ask if the user wants to convert it
                if ask_convert_address() {
                    match try_convert_option_to_token_address(&address) {
                        Ok(hash) => {
                            if let Some(addr_str) = &address {
                                tprintln!(ctx, "Successfully converted wallet address to token address:");
                                tprintln!(ctx, "  Wallet address: {}", addr_str);
                                tprintln!(ctx, "  Token address: {}", hex::encode(&hash));
                            }
                            hash
                        },
                        Err(e) => return Err(format!("Failed to convert address: {}", e).into()),
                    }
                } else {
                    return Err(format!("Invalid address format: {}", e).into());
                }
            }
        };

        // Get contract state
        let rpc = ctx.rpc_api();
        let response = rpc.get_contract_state(instance_id.clone()).await?;

        if !response.has_state {
            return Err("No state found for the specified instance ID".into());
        }

        // Determine contract type if not specified
        if contract_id.is_none() {
            // Try to get contract info from the instance
            let contracts_response = rpc.list_contracts().await?;
            for contract in contracts_response.contracts {
                if contract.instance_id == instance_id {
                    contract_id = Some(contract.contract_id);
                    break;
                }
            }
            
            if contract_id.is_none() {
                return Err("Could not determine contract ID. Please specify with --contract".into());
            }
        }

        let contract_id = contract_id.unwrap();
        
        // Process based on contract type
        match contract_id {
            100 => {
                // CX20 Extended Token
                match decode_cx20_state(&response.state) {
                    Ok(state) => {
                        let balance = get_cx20_balance(&state, &address_hash);
                        tprintln!(ctx, "Token balance for address {}:", option_string_to_display(&address, "unknown"));
                        tprintln!(ctx, "  Balance: {}", balance);
                        
                        // Show additional token info if available
                        if state.has_metadata() {
                            if let Some(decimals) = state.decimals {
                                tprintln!(ctx, "  Decimals: {}", decimals);
                            }
                        }
                        
                        // Show if address is frozen
                        if state.has_freeze() && state.is_frozen(&address_hash) {
                            tprintln!(ctx, "  Status: FROZEN");
                        }
                    },
                    Err(e) => return Err(format!("Failed to decode CX20 state: {}", e).into()),
                }
            },
            101 => {
                // CX20-MINI Token
                match decode_cx20_mini_state(&response.state) {
                    Ok(state) => {
                        let balance = get_cx20_mini_balance(&state, &address_hash);
                        tprintln!(ctx, "Token balance for address {}:", option_string_to_display(&address, "unknown"));
                        tprintln!(ctx, "  Balance: {}", balance);
                        tprintln!(ctx, "  Total Supply: {}", state.total_supply);
                    },
                    Err(e) => return Err(format!("Failed to decode CX20-MINI state: {}", e).into()),
                }
            },
            250 | 251 => {
                // Mining tokens (SHA3=250, BLAKE3=251)
                let token_type = if contract_id == 250 { "SHA3" } else { "BLAKE3" };
                match decode_cx_min_state(&response.state) {
                    Ok(state) => {
                        let balance = get_cx_min_balance(&state, &address_hash);
                        let bal_fmt = format_amount_with_decimals(balance, state.decimals);
                        let total_fmt = format_amount_with_decimals(state.total_supply, state.decimals);
                        let max_fmt = format_amount_with_decimals(state.max_supply, state.decimals);
                        let reward_fmt = format_amount_with_decimals(state.reward_per_block, state.decimals);
                        tprintln!(ctx, "Mining Token ({}) balance for address {}:", token_type, option_string_to_display(&address, "unknown"));
                        tprintln!(ctx, "  Decimals: {}", state.decimals);
                        tprintln!(ctx, "  Balance (raw): {}", balance);
                        tprintln!(ctx, "  Balance: {}", bal_fmt);
                        
                        // Show token metadata if available
                        if !state.name.is_empty() {
                            tprintln!(ctx, "  Name: {}", String::from_utf8_lossy(&state.name));
                        }
                        if !state.ticker.is_empty() {
                            tprintln!(ctx, "  Ticker: {}", String::from_utf8_lossy(&state.ticker));
                        }
                        
                        tprintln!(ctx, "  Total Supply: {} (raw {}))", total_fmt, state.total_supply);
                        tprintln!(ctx, "  Max Supply: {} (raw {})", max_fmt, state.max_supply);
                        tprintln!(ctx, "  Current Reward: {} (raw {})", reward_fmt, state.reward_per_block);
                        tprintln!(ctx, "  Blocks Mined: {}", state.blocks_mined);
                    },
                    Err(e) => return Err(format!("Failed to decode CX-MIN state: {}", e).into()),
                }
            },
            _ => {
                tprintln!(ctx, "Unknown or unsupported token contract type: {}", contract_id);
                tprintln!(ctx, "Balance checking is currently supported for token contracts (100, 101, 250, 251)");
            }
        }

        Ok(())
    }

    async fn send(self: Arc<Self>, ctx: Arc<CryptixCli>, argv: Vec<String>) -> Result<()> {
        let mut instance_id: Option<String> = None;
        let mut from_address: Option<String> = None;
        let mut to_address: Option<String> = None;
        let mut amount_str: Option<String> = None;
        let mut contract_id: Option<u64> = None;
        let mut fee: Option<i64> = None;

        let mut i = 0;
        while i < argv.len() {
            match argv[i].as_str() {
                "--instance" => {
                    if i + 1 < argv.len() {
                        instance_id = Some(argv[i + 1].clone());
                        i += 2;
                    } else {
                        return Err("Missing instance ID".into());
                    }
                }
                "--from" => {
                    if i + 1 < argv.len() {
                        from_address = Some(argv[i + 1].clone());
                        i += 2;
                    } else {
                        return Err("Missing from address".into());
                    }
                }
                "--to" => {
                    if i + 1 < argv.len() {
                        to_address = Some(argv[i + 1].clone());
                        i += 2;
                    } else {
                        return Err("Missing to address".into());
                    }
                }
                "--amount" => {
                    if i + 1 < argv.len() {
                        amount_str = Some(argv[i + 1].clone());
                        i += 2;
                    } else {
                        return Err("Missing amount".into());
                    }
                }
                "--contract" => {
                    if i + 1 < argv.len() {
                        contract_id = Some(argv[i + 1].parse::<u64>().map_err(|_| "Invalid contract ID")?);
                        i += 2;
                    } else {
                        return Err("Missing contract ID".into());
                    }
                }
                "--fee" => {
                    if i + 1 < argv.len() {
                        fee = Some(try_parse_optional_cryptix_as_sompi_i64(Some(&argv[i + 1]))?.unwrap_or(0));
                        i += 2;
                    } else {
                        return Err("Missing fee amount".into());
                    }
                }
                _ => {
                    return Err(format!("Unknown argument: {}", argv[i]).into());
                }
            }
        }

        let instance_id = instance_id.ok_or("Instance ID is required")?;
        let amount_input = amount_str.ok_or("Amount is required")?;

        // Convert from address to token address hash
        let from_hash = match try_convert_option_to_token_address(&from_address) {
            Ok(hash) => hash,
            Err(e) => {
                if ask_convert_address() {
                    match try_convert_option_to_token_address(&from_address) {
                        Ok(hash) => {
                            if let Some(addr_str) = &from_address {
                                tprintln!(ctx, "Successfully converted 'from' wallet address to token address:");
                                tprintln!(ctx, "  Wallet address: {}", addr_str);
                                tprintln!(ctx, "  Token address: {}", hex::encode(&hash));
                            }
                            hash
                        },
                        Err(e) => return Err(format!("Failed to convert 'from' address: {}", e).into()),
                    }
                } else {
                    return Err(format!("Invalid 'from' address format: {}", e).into());
                }
            }
        };

        // Convert to address to token address hash
        let to_hash = match try_convert_option_to_token_address(&to_address) {
            Ok(hash) => hash,
            Err(e) => {
                if ask_convert_address() {
                    match try_convert_option_to_token_address(&to_address) {
                        Ok(hash) => {
                            if let Some(addr_str) = &to_address {
                                tprintln!(ctx, "Successfully converted 'to' wallet address to token address:");
                                tprintln!(ctx, "  Wallet address: {}", addr_str);
                                tprintln!(ctx, "  Token address: {}", hex::encode(&hash));
                            }
                            hash
                        },
                        Err(e) => return Err(format!("Failed to convert 'to' address: {}", e).into()),
                    }
                } else {
                    return Err(format!("Invalid 'to' address format: {}", e).into());
                }
            }
        };

        // Get contract state and determine contract type if not specified
        let rpc = ctx.rpc_api();
        
        if contract_id.is_none() {
            // Try to get contract info from the instance
            let contracts_response = rpc.list_contracts().await?;
            for contract in contracts_response.contracts {
                if contract.instance_id == instance_id {
                    contract_id = Some(contract.contract_id);
                    break;
                }
            }
            
            if contract_id.is_none() {
                return Err("Could not determine contract ID. Please specify with --contract".into());
            }
        }

        let contract_id = contract_id.unwrap();
        
        // Process based on contract type
        match contract_id {
            100 => {
                // CX20 Extended Token - Use action_id 3 for transfer
                let action_id: u16 = 3; // transfer action
                
                // Parse amount as integer
                let amount = amount_input.parse::<u64>().map_err(|_| "Invalid amount")?;

                
                // Use secure token transfer
                secure_token_transfer(
                    ctx.clone(),
                    instance_id.clone(),
                    from_hash,
                    to_hash,
                    amount,
                    action_id,
                    fee,
                    from_address.clone(),
                    to_address.clone(),
                    amount.to_string(),
                ).await?;
            },
            101 => {
                // CX20-MINI Token - Use action_id 1 for transfer
                let action_id: u16 = 1; // transfer action
                
                // Parse amount as integer
                let amount = amount_input.parse::<u64>().map_err(|_| "Invalid amount")?;
                
                
                // Use secure token transfer
                secure_token_transfer(
                    ctx.clone(),
                    instance_id.clone(),
                    from_hash,
                    to_hash,
                    amount,
                    action_id,
                    fee,
                    from_address.clone(),
                    to_address.clone(),
                    amount.to_string(),
                ).await?;
            },
            250 | 251 => {
                // Mining token contracts (SHA3=250, BLAKE3=251)
                let token_type = if contract_id == 250 { "CX-MIN-SHA3" } else { "CX-MIN-BLAKE3" };
                let action_id: u16 = 2; // transfer action
                
                // Get contract state to check decimals
                let response_state = rpc.get_contract_state(instance_id.clone()).await?;
                let state = decode_cx_min_state(&response_state.state)?;
                
                // Parse amount with decimals
                let amount = if state.decimals > 0 {
                    parse_amount_with_decimals(&amount_input, state.decimals)?
                } else {
                    amount_input.parse::<u64>().map_err(|_| "Invalid amount")?
                };
                
                // Format amount for display
                let amount_display = if state.decimals > 0 {
                    format!("{} ({} raw units)", 
                        format_amount_with_decimals(amount, state.decimals), 
                        amount)
                } else {
                    amount.to_string()
                };
                
                // Use secure token transfer
                secure_token_transfer(
                    ctx.clone(),
                    instance_id.clone(),
                    from_hash,
                    to_hash,
                    amount,
                    action_id,
                    fee,
                    from_address.clone(),
                    to_address.clone(),
                    amount_display,
                ).await?;
            },
            _ => {
                return Err(format!("Unsupported token contract type: {}. Token transfer is currently supported for contracts 100, 101, 250, and 251", contract_id).into());
            }
        }

        Ok(())
    }

    async fn deploy(self: Arc<Self>, ctx: Arc<CryptixCli>, argv: Vec<String>) -> Result<()> {
        let mut contract_id: Option<u64> = None;
        let mut admin_address: Option<String> = None;
        let mut initial_supply: Option<u64> = None;
        let mut max_supply: Option<u64> = None;
        let mut name: Option<String> = None;
        let mut ticker: Option<String> = None;
        let mut fee: Option<i64> = None;
        let mut deflation_ppm: Option<u32> = None;

        let mut i = 0;
        while i < argv.len() {
            match argv[i].as_str() {
                "--contract" => {
                    if i + 1 < argv.len() {
                        contract_id = Some(argv[i + 1].parse::<u64>().map_err(|_| "Invalid contract ID")?);
                        i += 2;
                    } else {
                        return Err("Missing contract ID".into());
                    }
                }
                "--admin" => {
                    if i + 1 < argv.len() {
                        admin_address = Some(argv[i + 1].clone());
                        i += 2;
                    } else {
                        return Err("Missing admin address".into());
                    }
                }
                "--initial-supply" => {
                    if i + 1 < argv.len() {
                        initial_supply = Some(argv[i + 1].parse::<u64>().map_err(|_| "Invalid initial supply")?);
                        i += 2;
                    } else {
                        return Err("Missing initial supply".into());
                    }
                }
                "--max-supply" => {
                    if i + 1 < argv.len() {
                        max_supply = Some(argv[i + 1].parse::<u64>().map_err(|_| "Invalid max supply")?);
                        i += 2;
                    } else {
                        return Err("Missing max supply".into());
                    }
                }
                "--name" => {
                    if i + 1 < argv.len() {
                        name = Some(argv[i + 1].clone());
                        i += 2;
                    } else {
                        return Err("Missing name".into());
                    }
                }
                "--ticker" => {
                    if i + 1 < argv.len() {
                        ticker = Some(argv[i + 1].clone());
                        i += 2;
                    } else {
                        return Err("Missing ticker".into());
                    }
                }
                "--fee" => {
                    if i + 1 < argv.len() {
                        fee = Some(try_parse_optional_cryptix_as_sompi_i64(Some(&argv[i + 1]))?.unwrap_or(0));
                        i += 2;
                    } else {
                        return Err("Missing fee amount".into());
                    }
                }
                "--deflation-ppm" => {
                    if i + 1 < argv.len() {
                        deflation_ppm = Some(argv[i + 1].parse::<u32>().map_err(|_| "Invalid deflation PPM")?);
                        i += 2;
                    } else {
                        return Err("Missing deflation PPM".into());
                    }
                }
                _ => {
                    return Err(format!("Unknown argument: {}", argv[i]).into());
                }
            }
        }

        let contract_id = contract_id.ok_or("Contract ID is required")?;
        
        // Convert admin address to token address hash
        let admin_hash = match try_convert_option_to_token_address(&admin_address) {
            Ok(hash) => hash,
            Err(e) => {
                if ask_convert_address() {
                    match try_convert_option_to_token_address(&admin_address) {
                        Ok(hash) => {
                            if let Some(addr_str) = &admin_address {
                                tprintln!(ctx, "Successfully converted admin wallet address to token address:");
                                tprintln!(ctx, "  Wallet address: {}", addr_str);
                                tprintln!(ctx, "  Token address: {}", hex::encode(&hash));
                            }
                            hash
                        },
                        Err(e) => return Err(format!("Failed to convert admin address: {}", e).into()),
                    }
                } else {
                    return Err(format!("Invalid admin address format: {}", e).into());
                }
            }
        };

        // Prepare deployment data based on contract type
        let mut data = Vec::new();
        
        match contract_id {
            100 => {
                // CX20 Extended Token
                // Deploy data: admin (32 bytes) + flags (2 bytes) + initial_balances (variable)
                // For simplicity, we'll set flags to 0 (no metadata, no freeze, no allowances)
                data.extend_from_slice(&admin_hash);
                data.extend_from_slice(&0u16.to_le_bytes()); // flags = 0
                
                // No initial balances for now
                data.extend_from_slice(&0u16.to_le_bytes()); // num_balances = 0
                
                tprintln!(ctx, "Preparing to deploy CX20 Extended Token");
            },
            101 => {
                // CX20-MINI Token
                // Deploy data: owner (32 bytes) + initial_supply (8 bytes)
                let initial_supply = initial_supply.ok_or("Initial supply is required for CX20-MINI token")?;
                
                data.extend_from_slice(&admin_hash);
                data.extend_from_slice(&initial_supply.to_le_bytes());
                
                tprintln!(ctx, "Preparing to deploy CX20-MINI Token with initial supply: {}", initial_supply);
            },
            250 | 251 => {
                // Mining token contracts (SHA3=250, BLAKE3=251)
                let token_type = if contract_id == 250 { "CX-MIN-SHA3" } else { "CX-MIN-BLAKE3" };
                
                // Required parameters for mining tokens
                let initial_reward = initial_supply.ok_or(format!("Initial reward is required for {} token", token_type))?;
                let max_supply = max_supply.ok_or(format!("Max supply is required for {} token", token_type))?;
                let deflation_ppm = deflation_ppm.unwrap_or(0);
                
                // Deploy data: admin (32 bytes) + initial_reward (8 bytes) + max_supply (8 bytes) + deflation_ppm (4 bytes) + difficulty_bits (1 byte)
                data.extend_from_slice(&admin_hash);
                data.extend_from_slice(&initial_reward.to_le_bytes());
                data.extend_from_slice(&max_supply.to_le_bytes());
                data.extend_from_slice(&deflation_ppm.to_le_bytes());
                data.push(1u8); // initial difficulty bits = 1
                
            // Add optional metatags if provided
            if let Some(name_str) = &name {
                let name_bytes = name_str.as_bytes();
                if name_bytes.len() > u16::MAX as usize {
                    return Err("Name too long".into());
                }
                data.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
                data.extend_from_slice(name_bytes);
            } else {
                data.extend_from_slice(&0u16.to_le_bytes()); // empty name
            }
            
            if let Some(ticker_str) = &ticker {
                let ticker_bytes = ticker_str.as_bytes();
                if ticker_bytes.len() > u16::MAX as usize {
                    return Err("Ticker too long".into());
                }
                data.extend_from_slice(&(ticker_bytes.len() as u16).to_le_bytes());
                data.extend_from_slice(ticker_bytes);
            } else {
                data.extend_from_slice(&0u16.to_le_bytes()); // empty ticker
            }
            
            // Empty icon for now
            data.extend_from_slice(&0u16.to_le_bytes());
            
            // Add decimals (default to 0)
            data.push(0u8); // decimals = 0 (whole tokens)
                
                tprintln!(ctx, "Preparing to deploy {} Token:", token_type);
                tprintln!(ctx, "  Initial Reward: {}", initial_reward);
                tprintln!(ctx, "  Max Supply: {}", max_supply);
                tprintln!(ctx, "  Deflation PPM: {}", deflation_ppm);
                if let Some(n) = &name {
                    tprintln!(ctx, "  Name: {}", n);
                }
                if let Some(t) = &ticker {
                    tprintln!(ctx, "  Ticker: {}", t);
                }
            },
            _ => {
                return Err(format!("Unsupported token contract type: {}. Token deployment is currently supported for contracts 100, 101, 250, and 251", contract_id).into());
            }
        }

        // Check if wallet is open
        let wallet = ctx.wallet();
        if !wallet.is_open() {
            return Err("Wallet must be open to deploy token contracts securely".into());
        }

        // Get the account
        let account = ctx.account().await?;
        
        // Ask for wallet secret
        let abortable = Abortable::default();
        let (wallet_secret, payment_secret) = ctx.ask_wallet_secret(Some(&account)).await?;
        
        // Create a contract deployment payload using the proper format with magic bytes "CX\x01"
        // followed by CBOR-encoded contract payload
        let contract_payload = cryptix_consensus_core::contract::ContractPayload {
            v: 1,
            c: contract_id,
            a: 0, // 0 = deploy
            d: data.clone(),
        };
        let payload = contract_payload.encode().expect("Failed to encode contract payload");
        
        // Clone the context for use in the notifier
        let ctx_clone = ctx.clone();
        
        // Create a vector to collect transaction IDs during processing
        let tx_ids_during_processing = Arc::new(Mutex::new(Vec::new()));
        let tx_ids_for_notifier = tx_ids_during_processing.clone();
        
        // Use the wallet's send method to create and sign the transaction
        let priority_fee_sompi = fee.unwrap_or(0);
        
        tprintln!(ctx, "Signing and sending contract deployment transaction...");
        
        // Send to a dummy address with minimal amount, the real work is in the payload
        let dummy_address = account.receive_address()?; // Use own address as dummy
        let minimal_amount = 100_000_000; // 1 CPAY to avoid storage mass issues
        let outputs = PaymentOutputs::from((dummy_address.clone(), minimal_amount));
        
        let (summary, tx_ids) = account
            .send(
                outputs.into(),
                priority_fee_sompi.into(),
                Some(payload),
                wallet_secret,
                payment_secret,
                &abortable,
                Some(Arc::new(move |ptx| {
                    // Capture transaction IDs as they're being processed
                    let id = ptx.id();
                    tprintln!(ctx_clone, "Processing transaction: {}", id);
                    // Use a separate scope for the MutexGuard to ensure it's dropped before any await points
                    {
                        let mut ids = tx_ids_for_notifier.lock().unwrap();
                        ids.push(id);
                    }
                })),
            )
            .await?;

        tprintln!(ctx, "Token contract deployment - {summary}");
        tprintln!(ctx, "\nDeploying contract ID {} with secure transaction, tx ids:", contract_id);
        
        // Display the transaction IDs and get the first one for tracking
        let first_tx_id = {
            let ids = tx_ids_during_processing.lock().unwrap();
            
            // Display IDs from the processing
            if !ids.is_empty() {
                for id in ids.iter() {
                    tprintln!(ctx, "  {}", id);
                }
                Some(ids[0])
            } else if !tx_ids.is_empty() {
                // Display IDs from the result
                for tx_id in tx_ids.iter() {
                    tprintln!(ctx, "  {}", tx_id);
                }
                Some(tx_ids[0])
            } else {
                tprintln!(ctx, "  No transaction IDs available to display");
                None
            }
        };
        
        tprintln!(ctx, "\nNote: The contract deployment transaction has been securely signed with your wallet's private key.");
        
        // Wait for transaction confirmation and get instance ID
        if let Some(tx_id) = first_tx_id {
            
            tprintln!(ctx, "Waiting for transaction confirmation to get instance ID...");
            tprintln!(ctx, "This may take a few moments. Press Ctrl+C to stop waiting.");
            
            // Create a flag to track if we should continue waiting
            let continue_waiting = Arc::new(AtomicBool::new(true));
            let continue_waiting_clone = continue_waiting.clone();
            
            // Set up a Ctrl+C handler to allow the user to cancel waiting
            tokio::spawn(async move {
                if let Ok(_) = tokio::signal::ctrl_c().await {
                    continue_waiting_clone.store(false, Ordering::SeqCst);
                }
            });
            
            // Wait for the transaction to be confirmed and get the instance ID
            let max_attempts = 30; // Maximum number of attempts (30 * 2 seconds = 60 seconds max wait time)
            let mut instance_id = None;
            
            for attempt in 1..=max_attempts {
                if !continue_waiting.load(Ordering::SeqCst) {
                    tprintln!(ctx, "Waiting for confirmation was cancelled.");
                    break;
                }
                
                // Sleep for 2 seconds between checks
                tokio::time::sleep(Duration::from_secs(2)).await;
                
                // Check if the contract is now listed
                let rpc = ctx.rpc_api();
                match rpc.list_contracts().await {
                    Ok(response) => {
                        for contract in response.contracts {
                            if contract.contract_id == contract_id {
                                // Check if this contract's state outpoint matches our transaction
                                if contract.state_outpoint.transaction_id.to_string() == tx_id.to_string() {
                                    instance_id = Some(contract.instance_id.clone());
                                    break;
                                }
                            }
                        }
                        
                        if instance_id.is_some() {
                            break;
                        }
                    },
                    Err(e) => {
                        tprintln!(ctx, "Error checking for contract: {}", e);
                        // Continue trying despite errors
                    }
                }
                
                tprintln!(ctx, "Waiting for confirmation... (attempt {}/{})", attempt, max_attempts);
            }
            
            if let Some(id) = instance_id {
                tprintln!(ctx, "\nContract deployment confirmed!");
                tprintln!(ctx, "Contract instance ID: {}", id);
                tprintln!(ctx, "You can now use this instance ID with token commands.");
            } else {
                tprintln!(ctx, "\nCouldn't get instance ID within the timeout period.");
                tprintln!(ctx, "The contract may still be pending confirmation.");
                tprintln!(ctx, "You can check available contracts later with 'token list'.");
            }
        }

        Ok(())
    }

    async fn list(self: Arc<Self>, ctx: Arc<CryptixCli>, _argv: Vec<String>) -> Result<()> {
        // List all token contracts
        let rpc = ctx.rpc_api();
        let response = rpc.list_contracts().await?;

        if response.contracts.is_empty() {
            tprintln!(ctx, "No token contracts found");
            return Ok(());
        }

        let mut token_contracts = Vec::new();
        
        // Filter for token contracts (100, 101, 250, 251)
        for contract in response.contracts {
            if contract.contract_id == 100 || contract.contract_id == 101 || 
               contract.contract_id == 250 || contract.contract_id == 251 {
                token_contracts.push(contract);
            }
        }
        
        if token_contracts.is_empty() {
            tprintln!(ctx, "No token contracts found");
            return Ok(());
        }

        tprintln!(ctx, "Token contracts:");
        for contract in token_contracts {
            let contract_type = match contract.contract_id {
                100 => "CX20 Extended Token",
                101 => "CX20-MINI Token",
                250 => "CX-MIN-SHA3 Mining Token",
                251 => "CX-MIN-BLAKE3 Mining Token",
                _ => "Unknown Token Type",
            };
            
            tprintln!(ctx, "  Instance ID: {}", contract.instance_id);
            tprintln!(ctx, "    Type: {} (ID: {})", contract_type, contract.contract_id);
            tprintln!(ctx, "    State Size: {} bytes", contract.state_size);
            tprintln!(ctx, "    State Hash: {}", contract.state_hash);
            tprintln!(ctx, "    State Outpoint: {}:{}", contract.state_outpoint.transaction_id, contract.state_outpoint.index);
            tprintln!(ctx, "");
        }

        Ok(())
    }

    async fn info(self: Arc<Self>, ctx: Arc<CryptixCli>, argv: Vec<String>) -> Result<()> {
        let mut instance_id: Option<String> = None;
        let mut contract_id: Option<u64> = None;

        let mut i = 0;
        while i < argv.len() {
            match argv[i].as_str() {
                "--instance" => {
                    if i + 1 < argv.len() {
                        instance_id = Some(argv[i + 1].clone());
                        i += 2;
                    } else {
                        return Err("Missing instance ID".into());
                    }
                }
                "--contract" => {
                    if i + 1 < argv.len() {
                        contract_id = Some(argv[i + 1].parse::<u64>().map_err(|_| "Invalid contract ID")?);
                        i += 2;
                    } else {
                        return Err("Missing contract ID".into());
                    }
                }
                _ => {
                    return Err(format!("Unknown argument: {}", argv[i]).into());
                }
            }
        }

        let instance_id = instance_id.ok_or("Instance ID is required")?;

        // Get contract state
        let rpc = ctx.rpc_api();
        let response = rpc.get_contract_state(instance_id.clone()).await?;

        if !response.has_state {
            return Err("No state found for the specified instance ID".into());
        }

        // Determine contract type if not specified
        if contract_id.is_none() {
            // Try to get contract info from the instance
            let contracts_response = rpc.list_contracts().await?;
            for contract in contracts_response.contracts {
                if contract.instance_id == instance_id {
                    contract_id = Some(contract.contract_id);
                    break;
                }
            }
            
            if contract_id.is_none() {
                return Err("Could not determine contract ID. Please specify with --contract".into());
            }
        }

        let contract_id = contract_id.unwrap();
        
        // Process based on contract type
        match contract_id {
            100 => {
                // CX20 Extended Token
                match decode_cx20_state(&response.state) {
                    Ok(state) => {
                        tprintln!(ctx, "CX20 Extended Token Information:");
                        tprintln!(ctx, "  Admin: {}", hex::encode(state.admin));
                        
                        // Calculate total supply
                        let total_supply: u64 = state.balances.iter().map(|(_, amount)| amount).sum();
                        tprintln!(ctx, "  Total Supply: {}", total_supply);
                        
                        // Show metadata if available
                        if state.has_metadata() {
                            if let Some(decimals) = state.decimals {
                                tprintln!(ctx, "  Decimals: {}", decimals);
                            }
                            if let Some(symbol_hash) = &state.symbol_hash {
                                tprintln!(ctx, "  Symbol Hash: {}", hex::encode(symbol_hash));
                            }
                        }
                        
                        // Show freeze info if available
                        if state.has_freeze() {
                            if let Some(freeze_set) = &state.freeze_set {
                                tprintln!(ctx, "  Frozen Addresses: {}", freeze_set.len());
                            }
                        }
                        
                        // Show allowances if available
                        if let Some(allowances) = &state.allowances {
                            tprintln!(ctx, "  Allowances: {}", allowances.len());
                        }
                        
                        tprintln!(ctx, "  Balances: {}", state.balances.len());
                    },
                    Err(e) => return Err(format!("Failed to decode CX20 state: {}", e).into()),
                }
            },
            101 => {
                // CX20-MINI Token
                match decode_cx20_mini_state(&response.state) {
                    Ok(state) => {
                        tprintln!(ctx, "CX20-MINI Token Information:");
                        tprintln!(ctx, "  Owner: {}", hex::encode(state.owner));
                        tprintln!(ctx, "  Total Supply: {}", state.total_supply);
                        tprintln!(ctx, "  Balances: {}", state.balances.len());
                    },
                    Err(e) => return Err(format!("Failed to decode CX20-MINI state: {}", e).into()),
                }
            },
            250 | 251 => {
                // Mining tokens (SHA3=250, BLAKE3=251)
                let token_type_str = if contract_id == 250 { "CX-MIN-SHA3" } else { "CX-MIN-BLAKE3" };
                match decode_cx_min_state(&response.state) {
                    Ok(state) => {
                        tprintln!(ctx, "{} Mining Token Information:", token_type_str);
                        tprintln!(ctx, "  Admin: {}", hex::encode(state.admin));
                        tprintln!(ctx, "  Paused: {}", if state.paused != 0 { "Yes" } else { "No" });
                        
                        // Show token metadata if available
                        if !state.name.is_empty() {
                            tprintln!(ctx, "  Name: {}", String::from_utf8_lossy(&state.name));
                        }
                        if !state.ticker.is_empty() {
                            tprintln!(ctx, "  Ticker: {}", String::from_utf8_lossy(&state.ticker));
                        }
                        if !state.icon.is_empty() {
                            tprintln!(ctx, "  Icon: {} bytes", state.icon.len());
                        }
                        
                        // Show decimals if available
                        tprintln!(ctx, "  Decimals: {}", state.decimals);
                        
                        // Format amounts with decimals
                        tprintln!(ctx, "  Total Supply: {} ({} raw units)", 
                            format_amount_with_decimals(state.total_supply, state.decimals), 
                            state.total_supply);
                        tprintln!(ctx, "  Max Supply: {} ({} raw units)", 
                            format_amount_with_decimals(state.max_supply, state.decimals), 
                            state.max_supply);
                        tprintln!(ctx, "  Current Reward: {} ({} raw units)", 
                            format_amount_with_decimals(state.reward_per_block, state.decimals), 
                            state.reward_per_block);
                        tprintln!(ctx, "  Initial Reward: {} ({} raw units)", 
                            format_amount_with_decimals(state.initial_reward_per_block, state.decimals), 
                            state.initial_reward_per_block);
                        tprintln!(ctx, "  Deflation PPM: {}", state.deflation_ppm);
                        tprintln!(ctx, "  Last Deflation Height: {}", state.last_deflation_height);
                        tprintln!(ctx, "  Difficulty Bits: {}", state.difficulty_bits);
                        tprintln!(ctx, "  Target Interval (blocks): {}", state.target_interval_blocks);
                        tprintln!(ctx, "  Last Reward Height: {}", state.last_reward_height);
                        tprintln!(ctx, "  Blocks Mined: {}", state.blocks_mined);
                        tprintln!(ctx, "  Balances: {}", state.balances.len());
                    },
                    Err(e) => return Err(format!("Failed to decode CX-MIN state: {}", e).into()),
                }
            },
            _ => {
                return Err(format!("Unsupported token contract type: {}. Token info is currently supported for contracts 100, 101, 250, and 251", contract_id).into());
            }
        }

        Ok(())
    }

    async fn mine(&self, ctx: Arc<CryptixCli>, argv: Vec<String>) -> Result<()> {
        // Parse command-line arguments
        let mut instance_id: Option<String> = None;
        let mut reward_address: Option<String> = None;
        let mut threads: Option<usize> = None;
        let mut algo: Option<String> = None;
        let mut endpoint: Option<String> = None;
        let mut contract_id: Option<u64> = None;

        let mut i = 0;
        while i < argv.len() {
            match argv[i].as_str() {
                "--instance" => {
                    if i + 1 < argv.len() {
                        instance_id = Some(argv[i + 1].clone());
                        i += 2;
                    } else {
                        return Err("Missing instance ID".into());
                    }
                }
                "--reward-address" => {
                    if i + 1 < argv.len() {
                        reward_address = Some(argv[i + 1].clone());
                        i += 2;
                    } else {
                        return Err("Missing reward address".into());
                    }
                }
                "--threads" => {
                    if i + 1 < argv.len() {
                        threads = Some(argv[i + 1].parse::<usize>().map_err(|_| "Invalid thread count")?);
                        i += 2;
                    } else {
                        return Err("Missing thread count".into());
                    }
                }
                "--algo" => {
                    if i + 1 < argv.len() {
                        algo = Some(argv[i + 1].clone());
                        i += 2;
                    } else {
                        return Err("Missing algorithm".into());
                    }
                }
                "--endpoint" => {
                    if i + 1 < argv.len() {
                        endpoint = Some(argv[i + 1].clone());
                        i += 2;
                    } else {
                        return Err("Missing endpoint".into());
                    }
                }
                "--contract" => {
                    if i + 1 < argv.len() {
                        contract_id = Some(argv[i + 1].parse::<u64>().map_err(|_| "Invalid contract ID")?);
                        i += 2;
                    } else {
                        return Err("Missing contract ID".into());
                    }
                }
                _ => {
                    return Err(format!("Unknown argument: {}", argv[i]).into());
                }
            }
        }

        // Check if wallet is open
        let wallet = ctx.wallet();
        if !wallet.is_open() {  // Remove the .await since is_open() returns a bool, not a Future
            return Err("Wallet must be open to mine tokens".into());
        }

        // Get instance ID and contract ID
        let instance_id = instance_id.ok_or("Instance ID is required")?;

        // Determine contract type if not specified
        if contract_id.is_none() {
            // Try to get contract info from the instance
            let rpc = ctx.rpc_api();
            let contracts_response = rpc.list_contracts().await?;
            for contract in contracts_response.contracts {
                if contract.instance_id == instance_id {
                    contract_id = Some(contract.contract_id);
                    break;
                }
            }
            
            if contract_id.is_none() {
                return Err("Could not determine contract ID. Please specify with --contract".into());
            }
        }

        let contract_id = contract_id.unwrap();
        
        // Validate contract ID is a mining token (250 or 251)
        if contract_id != 250 && contract_id != 251 {
            return Err(format!("Contract ID {} is not a mining token contract. Use 250 for SHA3 or 251 for BLAKE3.", contract_id).into());
        }

        // Determine algorithm if not specified
        if algo.is_none() {
            algo = Some(if contract_id == 250 { "sha3".to_string() } else { "blake3".to_string() });
        }

        // Get reward address from wallet if not specified
        let reward_address = if let Some(addr) = reward_address {
            addr
        } else {
            // Get the first account address from the wallet
            let account = ctx.account().await?;
            let address = account.receive_address()?;
            tprintln!(ctx, "Using wallet address for rewards: {}", address);
            address.to_string()
        };

        // Set default thread count if not specified
        let threads = threads.unwrap_or_else(|| 4); // Default to 4 threads

        // Set default endpoint if not specified
        let endpoint = endpoint.unwrap_or_else(|| "grpc://127.0.0.1:19201".to_string());

        // Display mining configuration
        tprintln!(ctx, "Starting token mining with the following configuration:");
        tprintln!(ctx, "  Contract ID: {}", contract_id);
        tprintln!(ctx, "  Instance ID: {}", instance_id);
        tprintln!(ctx, "  Algorithm: {}", algo.as_ref().unwrap());
        tprintln!(ctx, "  Reward Address: {}", reward_address);
        tprintln!(ctx, "  Threads: {}", threads);
        tprintln!(ctx, "  Endpoint: {}", endpoint);
        tprintln!(ctx, "");
        tprintln!(ctx, "Mining will continue until you press Ctrl+C...");
        tprintln!(ctx, "");

        // Create a channel for mining solutions (unused in this implementation)
        let (_tx, _rx) = tokio::sync::mpsc::channel::<(Vec<u8>, u64)>(100);
        
        // Connect to the RPC endpoint
        let rpc = ctx.rpc_api();
        tprintln!(ctx, "Starting token miner...");
        tprintln!(ctx, "Connected to {}", endpoint);
        
        // Parse reward address to get miner hash
        let mut miner_hash = [0u8; 32];
        
        // Try to parse as hex first
        let mut s = reward_address.trim().to_string();
        if let Some(stripped) = s.strip_prefix("0x") {
            s = stripped.to_string();
        }
        
        match hex::decode(&s) {
            Ok(bytes) if bytes.len() == 32 => {
                miner_hash.copy_from_slice(&bytes);
                tprintln!(ctx, "Using hex-32 as miner identity.");
            }
            _ => {
                // If not valid hex, derive a 32-byte id from the raw string
                let h = blake3::hash(reward_address.as_bytes());
                miner_hash.copy_from_slice(h.as_bytes());
                tprintln!(ctx, "Using blake3 hash of address string as miner identity.");
            }
        }
        
        // Set up mining control flags
        let stop = Arc::new(AtomicBool::new(false));
        let submit_inflight = Arc::new(AtomicBool::new(false));
        let total_hashes = Arc::new(AtomicU64::new(0));
        let last_report = Arc::new(AtomicU64::new(now_millis()));
        
        // CTRL+C handler
        {
            let stop = stop.clone();
            let ctx_clone = ctx.clone();
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                tprintln!(ctx_clone, "CTRL+C received, stopping...");
                stop.store(true, Ordering::SeqCst);
            });
        }
        
        // Difficulty polling loop (every 3s)
        let diff_info = Arc::new(tokio::sync::RwLock::new(DifficultyInfo {
            paused: false,
            difficulty_bits: 1,
        }));
        
        {
            let diff_info = diff_info.clone();
            let instance = instance_id.clone();
            let rpc_clone = rpc.clone();
            let ctx_clone = ctx.clone();
            
            tokio::spawn(async move {
                loop {
                    match get_miner_difficulty(&rpc_clone, &instance).await {
                        Ok(info) => {
                            let mut w = diff_info.write().await;
                            *w = info;
                            tprintln!(ctx_clone, "Current difficulty: {} bits", info.difficulty_bits);
                            if info.paused {
                                tprintln!(ctx_clone, "Mining is currently paused by contract admin");
                            }
                        }
                        Err(e) => {
                            tprintln!(ctx_clone, "Difficulty poll error: {}", e.to_string());
                        }
                    }
                    tokio::time::sleep(Duration::from_secs(3)).await;
                }
            });
        }
        
        // Spawn worker threads
        let mut handles: Vec<JoinHandle<()>> = Vec::with_capacity(threads);
        for t in 0..threads {
            let rpc_clone = rpc.clone();
            let miner_hash = miner_hash;
            let stop = stop.clone();
            let submit_inflight = submit_inflight.clone();
            let total_hashes = total_hashes.clone();
            let last_report = last_report.clone();
            let diff_info = diff_info.clone();
            let algo = algo.clone().unwrap();
            let cid = contract_id;
            let ctx_clone = ctx.clone();
            let inst = instance_id.clone();
            
            let start_nonce = (t as u64) << 32;
            handles.push(tokio::spawn(async move {
                tprintln!(ctx_clone, "[worker {}] start_nonce={}", t, start_nonce);
                
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
                                tprintln!(ctx_clone, "hashrate ~{:.0} H/s", hps);
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
                    
                    // Pre-hash locally using the same preimage rule as the contract
                    let ok = match algo.as_str() {
                        "sha3" => precheck_sha3(cid, &miner_hash, nonce, snap.difficulty_bits),
                        "blake3" => precheck_blake3(cid, &miner_hash, nonce, snap.difficulty_bits),
                        _ => false,
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
                        
                        let rpc_ref = rpc_clone.clone();
                        let submit_inflight_ref = submit_inflight.clone();
                        let inst2 = inst.clone();
                        let ctx2 = ctx_clone.clone();
                        
                        // Submit async (don't block the loop)
                        tokio::spawn(async move {
                            let res = rpc_ref.submit_contract_call(inst2, 1, data).await;
                            match res {
                                Ok(resp) => {
                                    tprintln!(ctx2, "Submitted tx {}", resp.transaction_id);
                                }
                                Err(e) => {
                                    tprintln!(ctx2, "Submit error: {}", e.to_string());
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
        
        // Wait for CTRL+C or other stop signal
        let _ = tokio::signal::ctrl_c().await;
        stop.store(true, Ordering::SeqCst);
        
        // Wait for workers to finish
        for h in handles {
            let _ = h.await;
        }
        
        tprintln!(ctx, "Mining stopped.");
        Ok(())
    }
}
