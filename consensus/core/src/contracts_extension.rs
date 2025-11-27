//! Contracts Extension: CX-LP (380), CX-Revenue/FeeSplit (360), CX-Bridge (370)
//!

use crate::contract::{BlockContext, Contract, ContractError, MAX_CONTRACT_STATE_SIZE};
use std::collections::HashMap;

type AddressHash32 = [u8; 32];
type Hash32 = [u8; 32];

fn read_u64_le(s: &[u8]) -> Result<(u64, &[u8]), ContractError> {
    if s.len() < 8 {
        return Err(ContractError::InvalidState);
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&s[..8]);
    Ok((u64::from_le_bytes(buf), &s[8..]))
}
fn read_u32_le(s: &[u8]) -> Result<(u32, &[u8]), ContractError> {
    if s.len() < 4 {
        return Err(ContractError::InvalidState);
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&s[..4]);
    Ok((u32::from_le_bytes(buf), &s[4..]))
}
fn read_u16_le(s: &[u8]) -> Result<(u16, &[u8]), ContractError> {
    if s.len() < 2 {
        return Err(ContractError::InvalidState);
    }
    let mut buf = [0u8; 2];
    buf.copy_from_slice(&s[..2]);
    Ok((u16::from_le_bytes(buf), &s[2..]))
}
fn read_u8(s: &[u8]) -> Result<(u8, &[u8]), ContractError> {
    if s.is_empty() {
        return Err(ContractError::InvalidState);
    }
    Ok((s[0], &s[1..]))
}
fn read_hash32(s: &[u8]) -> Result<(Hash32, &[u8]), ContractError> {
    if s.len() < 32 {
        return Err(ContractError::InvalidState);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&s[..32]);
    Ok((out, &s[32..]))
}

fn encode_u64_le(v: u64, out: &mut Vec<u8>) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn encode_u32_le(v: u32, out: &mut Vec<u8>) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn encode_u16_le(v: u16, out: &mut Vec<u8>) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn encode_hash32(v: &[u8; 32], out: &mut Vec<u8>) {
    out.extend_from_slice(v);
}

#[inline]
fn ensure_state_limit(bytes: &[u8]) -> Result<(), ContractError> {
    if bytes.len() > MAX_CONTRACT_STATE_SIZE {
        return Err(ContractError::StateTooLarge);
    }
    Ok(())
}

// Deterministic integer sqrt for initial LP mint
fn integer_sqrt(x: u128) -> u64 {
    // Pure integer binary search sqrt(x), returning floor(sqrt(x))
    if x == 0 {
        return 0;
    }
    let mut lo: u128 = 0;
    let mut hi: u128 = (u64::MAX as u128).min(x);
    let mut ans: u128 = 0;
    while lo <= hi {
        let mid = (lo + hi) >> 1;
        let sq = mid.saturating_mul(mid);
        if sq <= x {
            ans = mid;
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }
    ans as u64
}

// Toy hash for deterministic proof_id (context-independent)
fn toy_hash(data: &[u8]) -> Hash32 {
    let mut h = [0u8; 32];
    for (i, &b) in data.iter().enumerate() {
        h[i % 32] ^= b.wrapping_add(i as u8);
    }
    h
}

/* ---------------------------
   CX-LP (ID = 380)
   --------------------------- */

pub struct CxLpContract;
pub static CX_LP_CONTRACT: CxLpContract = CxLpContract;

#[derive(Clone, Debug)]
struct CxLpState {
    token_a: Hash32,
    token_b: Hash32,
    fee_ppm: u32,
    admin: AddressHash32,
    reserve_a: u64,
    reserve_b: u64,
    lp_total_supply: u64,
    lp_balances: Vec<(AddressHash32, u64)>, // sorted by addr, no zeros
}

impl CxLpState {
    fn decode(mut s: &[u8]) -> Result<Self, ContractError> {
        let (token_a, r) = read_hash32(s)?; s = r;
        let (token_b, r) = read_hash32(s)?; s = r;
        let (fee_ppm, r) = read_u32_le(s)?; s = r;
        let (admin, r) = read_hash32(s)?; s = r;
        let (reserve_a, r) = read_u64_le(s)?; s = r;
        let (reserve_b, r) = read_u64_le(s)?; s = r;
        let (lp_total_supply, r) = read_u64_le(s)?; s = r;
        let (n, r) = read_u16_le(s)?; s = r;
        let mut lp_balances = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let (addr, r) = read_hash32(s)?; s = r;
            let (amt, r) = read_u64_le(s)?; s = r;
            lp_balances.push((addr, amt));
        }
        lp_balances.retain(|(_, a)| *a > 0);
        lp_balances.sort_by(|a, b| a.0.cmp(&b.0));
        lp_balances.dedup_by(|a, b| a.0 == b.0);
        Ok(Self { token_a, token_b, fee_ppm, admin, reserve_a, reserve_b, lp_total_supply, lp_balances })
    }

    fn encode(&self) -> Result<Vec<u8>, ContractError> {
        let mut token_a = self.token_a;
        let mut token_b = self.token_b;
        // Canonical token ordering
        if token_a > token_b {
            std::mem::swap(&mut token_a, &mut token_b);
        }
        let mut lp_balances = self.lp_balances.clone();
        lp_balances.retain(|(_, a)| *a > 0);
        lp_balances.sort_by(|a, b| a.0.cmp(&b.0));
        lp_balances.dedup_by(|a, b| a.0 == b.0);

        let mut out = Vec::new();
        encode_hash32(&token_a, &mut out);
        encode_hash32(&token_b, &mut out);
        encode_u32_le(self.fee_ppm, &mut out);
        encode_hash32(&self.admin, &mut out);
        encode_u64_le(self.reserve_a, &mut out);
        encode_u64_le(self.reserve_b, &mut out);
        encode_u64_le(self.lp_total_supply, &mut out);
        let n = u16::try_from(lp_balances.len()).map_err(|_| ContractError::StateTooLarge)?;
        encode_u16_le(n, &mut out);
        for (addr, amt) in lp_balances.iter() {
            encode_hash32(addr, &mut out);
            encode_u64_le(*amt, &mut out);
        }
        ensure_state_limit(&out)?;
        Ok(out)
    }

    fn lp_balance_index(&self, who: &AddressHash32) -> Option<usize> {
        self.lp_balances.binary_search_by(|e| e.0.cmp(who)).ok()
    }

    fn add_lp_balance(&mut self, who: AddressHash32, delta: u64) -> Result<(), ContractError> {
        match self.lp_balance_index(&who) {
            Some(i) => {
                self.lp_balances[i].1 = self.lp_balances[i].1.checked_add(delta).ok_or(ContractError::Custom(10))?;
                Ok(())
            }
            None => {
                match self.lp_balances.binary_search_by(|e| e.0.cmp(&who)) {
                    Ok(_) => unreachable!(),
                    Err(i) => self.lp_balances.insert(i, (who, delta)),
                }
                Ok(())
            }
        }
    }

    fn sub_lp_balance(&mut self, who: AddressHash32, delta: u64) -> Result<(), ContractError> {
        match self.lp_balance_index(&who) {
            Some(i) => {
                if self.lp_balances[i].1 < delta {
                    return Err(ContractError::Custom(1)); // InsufficientBalance
                }
                self.lp_balances[i].1 -= delta;
                if self.lp_balances[i].1 == 0 {
                    self.lp_balances.remove(i);
                }
                Ok(())
            }
            None => Err(ContractError::Custom(1)),
        }
    }
}

impl Contract for CxLpContract {
    fn apply(&self, state: &[u8], action_id: u16, data: &[u8], _ctx: &BlockContext) -> Result<Vec<u8>, ContractError> {
        ensure_state_limit(state)?;
        match action_id {
            0 => {
                // deploy(token_a, token_b, fee_ppm, admin)
                if !state.is_empty() {
                    return Err(ContractError::InvalidState);
                }
                if data.len() != 32 + 32 + 4 + 32 {
                    return Err(ContractError::InvalidState);
                }
                let mut p = data;
                let (token_a, r) = read_hash32(p)?; p = r;
                let (token_b, r) = read_hash32(p)?; p = r;
                let (fee_ppm, r) = read_u32_le(p)?; p = r;
                let (admin, _) = read_hash32(p)?;
                if fee_ppm > 1_000_000 {
                    return Err(ContractError::Custom(5)); // InvalidParam
                }
                let st = CxLpState {
                    token_a,
                    token_b,
                    fee_ppm,
                    admin,
                    reserve_a: 0,
                    reserve_b: 0,
                    lp_total_supply: 0,
                    lp_balances: Vec::new(),
                };
                return st.encode();
            }
            1 => {
                // add_liquidity(provider, amount_a, amount_b)
                if data.len() != 32 + 8 + 8 {
                    return Err(ContractError::InvalidState);
                }
                let mut p = data;
                let (provider, r) = read_hash32(p)?; p = r;
                let (amount_a, r) = read_u64_le(p)?; p = r;
                let (amount_b, _) = read_u64_le(p)?;
                if amount_a == 0 || amount_b == 0 {
                    return Err(ContractError::Custom(5));
                }
                let mut st = CxLpState::decode(state)?;
                let lp_mint = if st.lp_total_supply == 0 {
                    integer_sqrt((amount_a as u128) * (amount_b as u128))
                } else {
                    // floor math with u128 intermediates
                    let mint_a = (amount_a as u128) * (st.lp_total_supply as u128) / (st.reserve_a as u128);
                    let mint_b = (amount_b as u128) * (st.lp_total_supply as u128) / (st.reserve_b as u128);
                    mint_a.min(mint_b) as u64
                };
                if lp_mint == 0 {
                    return Err(ContractError::Custom(5));
                }
                st.reserve_a = st.reserve_a.checked_add(amount_a).ok_or(ContractError::Custom(10))?;
                st.reserve_b = st.reserve_b.checked_add(amount_b).ok_or(ContractError::Custom(10))?;
                st.lp_total_supply = st.lp_total_supply.checked_add(lp_mint).ok_or(ContractError::Custom(10))?;
                st.add_lp_balance(provider, lp_mint)?;
                return st.encode();
            }
            2 => {
                // remove_liquidity(provider, lp_amount)
                if data.len() != 32 + 8 {
                    return Err(ContractError::InvalidState);
                }
                let mut p = data;
                let (provider, r) = read_hash32(p)?; p = r;
                let (lp_amount, _) = read_u64_le(p)?;
                if lp_amount == 0 {
                    return Err(ContractError::Custom(5));
                }
                let mut st = CxLpState::decode(state)?;
                if st.lp_total_supply == 0 {
                    return Err(ContractError::Custom(5));
                }
                let amount_a = (lp_amount as u128) * (st.reserve_a as u128) / (st.lp_total_supply as u128);
                let amount_b = (lp_amount as u128) * (st.reserve_b as u128) / (st.lp_total_supply as u128);
                st.reserve_a = st.reserve_a.saturating_sub(amount_a as u64);
                st.reserve_b = st.reserve_b.saturating_sub(amount_b as u64);
                st.lp_total_supply = st.lp_total_supply.saturating_sub(lp_amount);
                st.sub_lp_balance(provider, lp_amount)?;
                return st.encode();
            }
            3 => {
                // swap_a_for_b(amount_in)
                if data.len() != 8 {
                    return Err(ContractError::InvalidState);
                }
                let (amount_in, _) = read_u64_le(data)?;
                if amount_in == 0 {
                    return Err(ContractError::Custom(5));
                }
                let mut st = CxLpState::decode(state)?;
                if st.reserve_a == 0 || st.reserve_b == 0 {
                    return Err(ContractError::Custom(5));
                }
                // Enforce XYK non-increasing: only the effective amount enters the pool
                let k = (st.reserve_a as u128) * (st.reserve_b as u128);
                let amount_in_eff = (amount_in as u128) * (1_000_000u128 - st.fee_ppm as u128) / 1_000_000u128;
                if amount_in_eff == 0 {
                    return Err(ContractError::Custom(5)); // no effective input
                }
                let new_reserve_a_u128 = (st.reserve_a as u128).saturating_add(amount_in_eff);
                if new_reserve_a_u128 > u64::MAX as u128 {
                    return Err(ContractError::Custom(10));
                }
                let new_reserve_b_u128 = k / new_reserve_a_u128; // floor
                if new_reserve_b_u128 >= st.reserve_b as u128 {
                    return Err(ContractError::Custom(5)); // no output
                }
                st.reserve_a = new_reserve_a_u128 as u64;
                st.reserve_b = new_reserve_b_u128 as u64;
                return st.encode();
            }
            4 => {
                // swap_b_for_a(amount_in)
                if data.len() != 8 {
                    return Err(ContractError::InvalidState);
                }
                let (amount_in, _) = read_u64_le(data)?;
                if amount_in == 0 {
                    return Err(ContractError::Custom(5));
                }
                let mut st = CxLpState::decode(state)?;
                if st.reserve_a == 0 || st.reserve_b == 0 {
                    return Err(ContractError::Custom(5));
                }
                let k = (st.reserve_a as u128) * (st.reserve_b as u128);
                let amount_in_eff = (amount_in as u128) * (1_000_000u128 - st.fee_ppm as u128) / 1_000_000u128;
                if amount_in_eff == 0 {
                    return Err(ContractError::Custom(5)); // no effective input
                }
                let new_reserve_b_u128 = (st.reserve_b as u128).saturating_add(amount_in_eff);
                if new_reserve_b_u128 > u64::MAX as u128 {
                    return Err(ContractError::Custom(10));
                }
                let new_reserve_a_u128 = k / new_reserve_b_u128; // floor
                if new_reserve_a_u128 >= st.reserve_a as u128 {
                    return Err(ContractError::Custom(5));
                }
                st.reserve_b = new_reserve_b_u128 as u64;
                st.reserve_a = new_reserve_a_u128 as u64;
                return st.encode();
            }
            5 => {
                // set_fee(caller, fee_ppm)
                if data.len() != 32 + 4 {
                    return Err(ContractError::InvalidState);
                }
                let mut p = data;
                let (caller, r) = read_hash32(p)?; p = r;
                let (fee_ppm, _) = read_u32_le(p)?;
                if fee_ppm > 1_000_000 {
                    return Err(ContractError::Custom(5));
                }
                let mut st = CxLpState::decode(state)?;
                if caller != st.admin {
                    return Err(ContractError::Custom(2)); // NotAdmin
                }
                st.fee_ppm = fee_ppm;
                return st.encode();
            }
            6 => {
                // set_admin(caller, new_admin)
                if data.len() != 32 + 32 {
                    return Err(ContractError::InvalidState);
                }
                let mut p = data;
                let (caller, r) = read_hash32(p)?; p = r;
                let (new_admin, _) = read_hash32(p)?;
                let mut st = CxLpState::decode(state)?;
                if caller != st.admin {
                    return Err(ContractError::Custom(2));
                }
                st.admin = new_admin;
                return st.encode();
            }
            _ => Err(ContractError::InvalidAction),
        }
    }
}

/* ---------------------------
   CX-Revenue / FeeSplit (ID = 360)
   --------------------------- */

pub struct CxRevenueContract;
pub static CX_REVENUE_CONTRACT: CxRevenueContract = CxRevenueContract;

#[derive(Clone, Debug)]
struct CxRevenueState {
    admin: AddressHash32,
    recipients: Vec<(AddressHash32, u64)>, // sorted by addr, no zero shares
    total_shares: u64,
    pending: HashMap<AddressHash32, u64>, // pruned zeros
}

impl CxRevenueState {
    fn decode(mut s: &[u8]) -> Result<Self, ContractError> {
        let (admin, r) = read_hash32(s)?; s = r;
        let (n, r) = read_u16_le(s)?; s = r;
        let mut recipients = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let (addr, r) = read_hash32(s)?; s = r;
            let (share, r) = read_u64_le(s)?; s = r;
            if share > 0 {
                recipients.push((addr, share));
            }
        }
        recipients.sort_by(|a, b| a.0.cmp(&b.0));
        recipients.dedup_by(|a, b| a.0 == b.0);

        // Stored total_shares (ignored, deterministically recomputed)
        let (_stored_ts, r) = read_u64_le(s)?; s = r;
        let mut total_shares_u128: u128 = 0;
        for (_, sh) in recipients.iter() {
            total_shares_u128 = total_shares_u128.checked_add(*sh as u128).ok_or(ContractError::Custom(10))?;
        }
        let total_shares = u64::try_from(total_shares_u128).map_err(|_| ContractError::Custom(10))?;

        let (m, r) = read_u16_le(s)?; s = r;
        let mut pending = HashMap::new();
        for _ in 0..m {
            let (addr, r) = read_hash32(s)?; s = r;
            let (amt, r) = read_u64_le(s)?; s = r;
            if amt > 0 {
                pending.insert(addr, amt);
            }
        }
        Ok(Self { admin, recipients, total_shares, pending })
    }

    fn encode(&self) -> Result<Vec<u8>, ContractError> {
        let mut recipients = self.recipients.clone();
        recipients.retain(|(_, s)| *s > 0);
        recipients.sort_by(|a, b| a.0.cmp(&b.0));
        recipients.dedup_by(|a, b| a.0 == b.0);

        // Canonical total_shares recomputed
        let mut total_shares_u128: u128 = 0;
        for (_, sh) in recipients.iter() {
            total_shares_u128 = total_shares_u128.checked_add(*sh as u128).ok_or(ContractError::Custom(10))?;
        }
        let total_shares = u64::try_from(total_shares_u128).map_err(|_| ContractError::Custom(10))?;

        let mut pending_vec: Vec<(AddressHash32, u64)> =
            self.pending.iter().filter(|(_, &v)| v > 0).map(|(&k, &v)| (k, v)).collect();
        pending_vec.sort_by(|a, b| a.0.cmp(&b.0));

        let mut out = Vec::new();
        encode_hash32(&self.admin, &mut out);
        let n = u16::try_from(recipients.len()).map_err(|_| ContractError::StateTooLarge)?;
        encode_u16_le(n, &mut out);
        for (addr, share) in recipients.iter() {
            encode_hash32(addr, &mut out);
            encode_u64_le(*share, &mut out);
        }
        encode_u64_le(total_shares, &mut out);
        let m = u16::try_from(pending_vec.len()).map_err(|_| ContractError::StateTooLarge)?;
        encode_u16_le(m, &mut out);
        for (addr, amt) in pending_vec.iter() {
            encode_hash32(addr, &mut out);
            encode_u64_le(*amt, &mut out);
        }
        ensure_state_limit(&out)?;
        Ok(out)
    }
}

impl Contract for CxRevenueContract {
    fn apply(&self, state: &[u8], action_id: u16, data: &[u8], _ctx: &BlockContext) -> Result<Vec<u8>, ContractError> {
        ensure_state_limit(state)?;
        match action_id {
            0 => {
                // deploy(recipients[], shares[], admin)
                // Data: [n:2][n*(addr:32,share:8)][admin:32]
                if !state.is_empty() {
                    return Err(ContractError::InvalidState);
                }
                if data.len() < 2 {
                    return Err(ContractError::InvalidState);
                }
                let (n, mut p) = read_u16_le(data)?;
                let need = (n as usize) * (32 + 8) + 32;
                if p.len() < need {
                    return Err(ContractError::InvalidState);
                }
                let mut recipients = Vec::with_capacity(n as usize);
                let mut total_shares = 0u64;
                for _ in 0..n {
                    let (addr, r) = read_hash32(p)?; p = r;
                    let (share, r) = read_u64_le(p)?; p = r;
                    if share > 0 {
                        recipients.push((addr, share));
                        total_shares = total_shares.checked_add(share).ok_or(ContractError::Custom(10))?;
                    }
                }
                let (admin, _) = read_hash32(p)?;
                if total_shares == 0 {
                    return Err(ContractError::InvalidState);
                }
                recipients.sort_by(|a, b| a.0.cmp(&b.0));
                recipients.dedup_by(|a, b| a.0 == b.0);
                let st = CxRevenueState { admin, recipients, total_shares, pending: HashMap::new() };
                return st.encode();
            }
            1 => {
                // deposit(amount)
                if data.len() != 8 {
                    return Err(ContractError::InvalidState);
                }
                let (amount, _) = read_u64_le(data)?;
                if amount == 0 {
                    return Err(ContractError::Custom(5));
                }
                let mut st = CxRevenueState::decode(state)?;
                if st.total_shares == 0 {
                    return Err(ContractError::InvalidState);
                }
                for (addr, share) in st.recipients.iter() {
                    let payout = (amount as u128) * (*share as u128) / (st.total_shares as u128);
                    let payout_u64 = payout as u64;
                    if payout_u64 > 0 {
                        let entry = st.pending.entry(*addr).or_insert(0);
                        *entry = entry.checked_add(payout_u64).ok_or(ContractError::Custom(10))?;
                    }
                }
                // Remainder deterministically discarded
                return st.encode();
            }
            2 => {
                // claim(caller)
                if data.len() != 32 {
                    return Err(ContractError::InvalidState);
                }
                let (caller, _) = read_hash32(data)?;
                let mut st = CxRevenueState::decode(state)?;
                if let Some(amt) = st.pending.get_mut(&caller) {
                    if *amt == 0 {
                        return Err(ContractError::Custom(1)); // NoClaimable
                    }
                    *amt = 0;
                    st.pending.remove(&caller);
                } else {
                    return Err(ContractError::Custom(1));
                }
                return st.encode();
            }
            3 => {
                // set_shares(caller, recipients[], shares[])
                if data.len() < 32 + 2 {
                    return Err(ContractError::InvalidState);
                }
                let mut p = data;
                let (caller, r) = read_hash32(p)?; p = r;
                let (n, r) = read_u16_le(p)?; p = r;
                let need = (n as usize) * (32 + 8);
                if p.len() < need {
                    return Err(ContractError::InvalidState);
                }
                let mut recipients = Vec::with_capacity(n as usize);
                let mut total_shares = 0u64;
                for _ in 0..n {
                    let (addr, r) = read_hash32(p)?; p = r;
                    let (share, r) = read_u64_le(p)?; p = r;
                    if share > 0 {
                        recipients.push((addr, share));
                        total_shares = total_shares.checked_add(share).ok_or(ContractError::Custom(10))?;
                    }
                }
                let mut st = CxRevenueState::decode(state)?;
                if caller != st.admin {
                    return Err(ContractError::Custom(2)); // NotAdmin
                }
                if total_shares == 0 {
                    return Err(ContractError::Custom(5)); // InvalidParam
                }
                recipients.sort_by(|a, b| a.0.cmp(&b.0));
                recipients.dedup_by(|a, b| a.0 == b.0);
                st.recipients = recipients;
                st.total_shares = total_shares;
                return st.encode();
            }
            4 => {
                // set_admin(caller, new_admin)
                if data.len() != 32 + 32 {
                    return Err(ContractError::InvalidState);
                }
                let mut p = data;
                let (caller, r) = read_hash32(p)?; p = r;
                let (new_admin, _) = read_hash32(p)?;
                let mut st = CxRevenueState::decode(state)?;
                if caller != st.admin {
                    return Err(ContractError::Custom(2)); // NotAdmin
                }
                st.admin = new_admin;
                return st.encode();
            }
            _ => Err(ContractError::InvalidAction),
        }
    }
}

/* ---------------------------
   CX-Bridge (ID = 370)
   --------------------------- */

pub struct CxBridgeContract;
pub static CX_BRIDGE_CONTRACT: CxBridgeContract = CxBridgeContract;

#[derive(Clone, Debug)]
struct CxBridgeState {
    validators: Vec<AddressHash32>, // sorted unique
    threshold: u16,
    paused: u8,
    processed_proofs: Vec<Hash32>, // sorted unique
}

impl CxBridgeState {
    fn decode(mut s: &[u8]) -> Result<Self, ContractError> {
        let (paused, r) = read_u8(s)?; s = r;
        let (threshold, r) = read_u16_le(s)?; s = r;
        let (n_val, r) = read_u16_le(s)?; s = r;
        let mut validators = Vec::with_capacity(n_val as usize);
        for _ in 0..n_val {
            let (v, r) = read_hash32(s)?; s = r;
            validators.push(v);
        }
        validators.sort(); validators.dedup();
        let (n_pf, r) = read_u16_le(s)?; s = r;
        let mut processed_proofs = Vec::with_capacity(n_pf as usize);
        for _ in 0..n_pf {
            let (pf, r) = read_hash32(s)?; s = r;
            processed_proofs.push(pf);
        }
        processed_proofs.sort(); processed_proofs.dedup();
        Ok(Self { validators, threshold, paused, processed_proofs })
    }

    fn encode(&self) -> Result<Vec<u8>, ContractError> {
        let mut validators = self.validators.clone();
        validators.sort(); validators.dedup();
        let mut processed_proofs = self.processed_proofs.clone();
        processed_proofs.sort(); processed_proofs.dedup();

        let mut out = Vec::new();
        out.push(self.paused);
        encode_u16_le(self.threshold, &mut out);
        let n_val = u16::try_from(validators.len()).map_err(|_| ContractError::StateTooLarge)?;
        encode_u16_le(n_val, &mut out);
        for v in validators.iter() { encode_hash32(v, &mut out); }
        let n_pf = u16::try_from(processed_proofs.len()).map_err(|_| ContractError::StateTooLarge)?;
        encode_u16_le(n_pf, &mut out);
        for pf in processed_proofs.iter() { encode_hash32(pf, &mut out); }
        ensure_state_limit(&out)?;
        Ok(out)
    }

    fn validator_index(&self, who: &AddressHash32) -> Option<usize> {
        self.validators.binary_search(who).ok()
    }

    fn is_processed(&self, proof_id: &Hash32) -> bool {
        self.processed_proofs.binary_search(proof_id).is_ok()
    }
}

impl Contract for CxBridgeContract {
    fn apply(&self, state: &[u8], action_id: u16, data: &[u8], _ctx: &BlockContext) -> Result<Vec<u8>, ContractError> {
        ensure_state_limit(state)?;
        match action_id {
            0 => { // deploy(validators[], threshold)
                if !state.is_empty() { return Err(ContractError::InvalidState); }
                if data.len() < 2 { return Err(ContractError::InvalidState); }
                let (n, mut p) = read_u16_le(data)?;
                let need = (n as usize) * 32 + 2;
                if p.len() < need { return Err(ContractError::InvalidState); }
                let mut validators = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    let (v, r) = read_hash32(p)?; p = r;
                    validators.push(v);
                }
                let (threshold, _) = read_u16_le(p)?;
                if threshold == 0 || threshold as usize > validators.len() { return Err(ContractError::InvalidState); }
                validators.sort(); validators.dedup();
                let st = CxBridgeState { validators, threshold, paused: 0, processed_proofs: Vec::new() };
                return st.encode();
            }
            1 => { // lock(token, amount, receiver_hash, target_chain_id)
                if data.len() != 32 + 8 + 32 + 4 { return Err(ContractError::InvalidState); }
                let mut st = CxBridgeState::decode(state)?;
                if st.paused != 0 { return Err(ContractError::Custom(9)); } // Paused
                // State-only placeholder, no external effects
                return st.encode();
            }
            2 => { // release(proof_bytes)
                if data.is_empty() { return Err(ContractError::InvalidState); }
                let proof_id = toy_hash(data);
                let mut st = CxBridgeState::decode(state)?;
                if st.paused != 0 { return Err(ContractError::Custom(9)); }
                if st.is_processed(&proof_id) { return Err(ContractError::Custom(4)); } // AlreadyProcessed
                match st.processed_proofs.binary_search(&proof_id) {
                    Ok(_) => return Err(ContractError::Custom(4)),
                    Err(i) => st.processed_proofs.insert(i, proof_id),
                }
                return st.encode();
            }
            3 => { // verify_proof(proof_bytes)
                if data.is_empty() { return Err(ContractError::InvalidState); }
                let mut st = CxBridgeState::decode(state)?;
                if st.paused != 0 { return Err(ContractError::Custom(9)); }
                // Deterministic success without changing state
                return st.encode();
            }
            4 => { // set_validators(validators[], threshold)
                if data.len() < 2 { return Err(ContractError::InvalidState); }
                let (n, mut p) = read_u16_le(data)?;
                let need = (n as usize) * 32 + 2;
                if p.len() < need { return Err(ContractError::InvalidState); }
                let mut validators = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    let (v, r) = read_hash32(p)?; p = r;
                    validators.push(v);
                }
                let (threshold, _) = read_u16_le(p)?;
                if threshold == 0 || threshold as usize > validators.len() { return Err(ContractError::Custom(5)); }
                let mut st = CxBridgeState::decode(state)?;
                if st.paused != 0 { return Err(ContractError::Custom(9)); }
                validators.sort(); validators.dedup();
                st.validators = validators;
                st.threshold = threshold;
                return st.encode();
            }
            5 => { // pause()
                if !data.is_empty() { return Err(ContractError::InvalidState); }
                let mut st = CxBridgeState::decode(state)?;
                st.paused = 1;
                return st.encode();
            }
            6 => { // unpause()
                if !data.is_empty() { return Err(ContractError::InvalidState); }
                let mut st = CxBridgeState::decode(state)?;
                st.paused = 0;
                return st.encode();
            }
            _ => Err(ContractError::InvalidAction),
        }
    }
}

/* =========================
   CX-MIN-SHA3 (ID = 250) and CX-MIN-BLAKE3 (ID = 251)
   ========================= */

const CXMIN_MONTH_BLOCKS: u64 = 30 * 24 * 60 * 60; // 2_592_000 blocks (1 block per second)
const CXMIN_MIN_INTERVAL_BLOCKS: u64 = 30;
const CXMIN_TARGET_INTERVAL_BLOCKS: u64 = 60;
const CXMIN_MAX_METATAG_SIZE: usize = 500; // Maximum size for all metatags combined
const CXMIN_MIN_DIFF_BITS: u8 = 1;
const CXMIN_MAX_DIFF_BITS: u8 = 250;
const CXMIN_MAX_DEFLATION_PPM: u32 = 1_000_000; // 100%

#[derive(Clone, Debug)]
struct CxMinState {
    // Admin & Flags
    admin: AddressHash32,
    paused: u8, // 0 active, 1 paused
    // Tokenomics
    total_supply: u64,
    max_supply: u64,
    reward_per_block: u64,
    initial_reward_per_block: u64,
    deflation_ppm: u32,
    last_deflation_height: u64,
    // PoW/Difficulty
    difficulty_bits: u8,
    target_interval_blocks: u64,
    last_reward_height: u64,
    blocks_mined: u64,
    // Balances
    balances: Vec<(AddressHash32, u64)>, // sorted, unique, no zero
    // Metatags
    name: Vec<u8>,
    ticker: Vec<u8>,
    icon: Vec<u8>,
    // Decimals (optional; 0 if omitted)
    decimals: u8,
}

impl CxMinState {
    fn decode(mut s: &[u8]) -> Result<Self, ContractError> {
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
        balances.sort_by(|a,b| a.0.cmp(&b.0));
        balances.dedup_by(|a,b| a.0 == b.0);

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

        // Optional decimals at the end
        let mut decimals: u8 = 0;
        if !s.is_empty() {
            let (d, _r) = read_u8(s)?;
            decimals = d;
        }

        Ok(Self {
            admin, paused,
            total_supply, max_supply, reward_per_block, initial_reward_per_block,
            deflation_ppm, last_deflation_height,
            difficulty_bits, target_interval_blocks, last_reward_height, blocks_mined,
            balances,
            name, ticker, icon,
            decimals,
        })
    }

    fn encode(&self) -> Result<Vec<u8>, ContractError> {
        let mut balances = self.balances.clone();
        balances.retain(|(_,a)| *a > 0);
        balances.sort_by(|a,b| a.0.cmp(&b.0));
        balances.dedup_by(|a,b| a.0 == b.0);

        let mut out = Vec::new();
        encode_hash32(&self.admin, &mut out);
        out.push(self.paused);

        encode_u64_le(self.total_supply, &mut out);
        encode_u64_le(self.max_supply, &mut out);
        encode_u64_le(self.reward_per_block, &mut out);
        encode_u64_le(self.initial_reward_per_block, &mut out);
        encode_u32_le(self.deflation_ppm, &mut out);
        encode_u64_le(self.last_deflation_height, &mut out);

        out.push(self.difficulty_bits);
        encode_u64_le(self.target_interval_blocks, &mut out);
        encode_u64_le(self.last_reward_height, &mut out);
        encode_u64_le(self.blocks_mined, &mut out);

        let n = u16::try_from(balances.len()).map_err(|_| ContractError::StateTooLarge)?;
        encode_u16_le(n, &mut out);
        for (addr, amt) in balances.iter() {
            encode_hash32(addr, &mut out);
            encode_u64_le(*amt, &mut out);
        }

        // Encode metatags
        let name_len = u16::try_from(self.name.len()).map_err(|_| ContractError::StateTooLarge)?;
        encode_u16_le(name_len, &mut out);
        out.extend_from_slice(&self.name);

        let ticker_len = u16::try_from(self.ticker.len()).map_err(|_| ContractError::StateTooLarge)?;
        encode_u16_le(ticker_len, &mut out);
        out.extend_from_slice(&self.ticker);

        let icon_len = u16::try_from(self.icon.len()).map_err(|_| ContractError::StateTooLarge)?;
        encode_u16_le(icon_len, &mut out);
        out.extend_from_slice(&self.icon);

        // Encode optional decimals (always present in new states)
        out.push(self.decimals);

        ensure_state_limit(&out)?;
        Ok(out)
    }

    fn balance_index(&self, who: &AddressHash32) -> Option<usize> {
        self.balances.binary_search_by(|e| e.0.cmp(who)).ok()
    }

    fn add_balance(&mut self, who: AddressHash32, amt: u64) -> Result<(), ContractError> {
        match self.balance_index(&who) {
            Some(i) => {
                self.balances[i].1 = self.balances[i].1.checked_add(amt).ok_or(ContractError::Custom(10))?;
                Ok(())
            }
            None => {
                match self.balances.binary_search_by(|e| e.0.cmp(&who)) {
                    Ok(_) => unreachable!(),
                    Err(i) => self.balances.insert(i, (who, amt)),
                }
                Ok(())
            }
        }
    }

    fn sub_balance(&mut self, who: AddressHash32, amt: u64) -> Result<(), ContractError> {
        match self.balance_index(&who) {
            Some(i) => {
                if self.balances[i].1 < amt { return Err(ContractError::Custom(1)); } // InsufficientBalance
                self.balances[i].1 -= amt;
                if self.balances[i].1 == 0 { self.balances.remove(i); }
                Ok(())
            }
            None => Err(ContractError::Custom(1)),
        }
    }
}

#[inline]
fn count_leading_zeros_256(h: &[u8;32]) -> u32 {
    let mut total: u32 = 0;
    for &b in h.iter() {
        if b == 0 {
            total += 8;
        } else {
            // For u8, leading_zeros() returns 0..=8 (already in 8-bit width)
            total += b.leading_zeros();
            break;
        }
    }
    total
}

fn apply_mine_common(
    mut st: CxMinState,
    miner: AddressHash32,
    nonce: u64,
    ctx: &BlockContext,
    contract_id: u64,
    use_sha3: bool
) -> Result<Vec<u8>, ContractError> {
    if st.paused != 0 { return Err(ContractError::Custom(20)); } // Paused
    if st.total_supply >= st.max_supply { return Err(ContractError::Custom(21)); } // EmissionFinished
    if st.blocks_mined > 0 && ctx.block_height < st.last_reward_height.saturating_add(CXMIN_MIN_INTERVAL_BLOCKS) {
        return Err(ContractError::Custom(22)); // MiningTooFast
    }

    // PoW hash
    let mut preimage = Vec::with_capacity(8 + 8 + 32 + 8 + 16);
    preimage.extend_from_slice(b"CXMIN_"); // prefix root
    if use_sha3 {
        preimage.extend_from_slice(b"SHA3");
    } else {
        preimage.extend_from_slice(b"BLK3");
    }
    preimage.extend_from_slice(&contract_id.to_be_bytes());
    preimage.extend_from_slice(&ctx.block_height.to_be_bytes());
    preimage.extend_from_slice(&miner);
    preimage.extend_from_slice(&nonce.to_be_bytes());

    let hash_bytes: [u8;32] = if use_sha3 {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(&preimage);
        let out = hasher.finalize();
        let mut h = [0u8;32]; h.copy_from_slice(&out[..]); h
    } else {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&preimage);
        let out = hasher.finalize();
        let mut h = [0u8;32]; h.copy_from_slice(out.as_bytes()); h
    };

    let zeros = count_leading_zeros_256(&hash_bytes);
    if zeros < st.difficulty_bits as u32 {
        return Err(ContractError::Custom(23)); // InvalidPoW
    }

    // Deflation (monthly periods since last_deflation_height)
    if ctx.block_height > st.last_deflation_height {
        let elapsed = ctx.block_height - st.last_deflation_height;
        let periods = elapsed / CXMIN_MONTH_BLOCKS;
        if periods > 0 {
            for _ in 0..periods {
                let ppm: u64 = st.deflation_ppm as u64;
                st.reward_per_block = st.reward_per_block.saturating_mul(1_000_000u64.saturating_sub(ppm)) / 1_000_000u64;
            }
            st.last_deflation_height = st.last_deflation_height.saturating_add(periods.saturating_mul(CXMIN_MONTH_BLOCKS));
        }
    }

    if st.reward_per_block == 0 {
        return Err(ContractError::Custom(24)); // RewardZero
    }

    let remaining = st.max_supply.saturating_sub(st.total_supply);
    if remaining == 0 {
        return Err(ContractError::Custom(21)); // EmissionFinished
    }
    let reward = st.reward_per_block.min(remaining);

    // Credit reward
    st.add_balance(miner, reward)?;
    st.total_supply = st.total_supply.checked_add(reward).ok_or(ContractError::Custom(10))?;
    let prev_last_reward_height = st.last_reward_height;
    st.blocks_mined = st.blocks_mined.saturating_add(1);
    st.last_reward_height = ctx.block_height;

    // Difficulty auto-adjustment
    if st.blocks_mined > 1 {
        let actual = ctx.block_height.saturating_sub(prev_last_reward_height);
        let target = st.target_interval_blocks;
        if actual < target {
            if st.difficulty_bits < CXMIN_MAX_DIFF_BITS {
                st.difficulty_bits += 1;
            }
        } else if actual > target {
            if st.difficulty_bits > CXMIN_MIN_DIFF_BITS {
                st.difficulty_bits -= 1;
            }
        }
    }

    st.encode()
}

pub struct CxMinSha3Contract;
pub struct CxMinBlake3Contract;

pub static CX_MIN_SHA3_CONTRACT: CxMinSha3Contract = CxMinSha3Contract;
pub static CX_MIN_BLAKE3_CONTRACT: CxMinBlake3Contract = CxMinBlake3Contract;

impl Contract for CxMinSha3Contract {
    fn apply(&self, state: &[u8], action_id: u16, data: &[u8], ctx: &BlockContext) -> Result<Vec<u8>, ContractError> {
        ensure_state_limit(state)?;
        match action_id {
            // 0 deploy(admin, initial_reward, max_supply, deflation_ppm, initial_difficulty_bits, [name, ticker, icon])
            0 => {
                if !state.is_empty() { return Err(ContractError::InvalidState); }
                if data.len() < 32 + 8 + 8 + 4 + 1 { return Err(ContractError::InvalidState); }
                let mut p = data;
                let (admin, r) = read_hash32(p)?; p = r;
                let (initial_reward, r) = read_u64_le(p)?; p = r;
                let (max_supply, r) = read_u64_le(p)?; p = r;
                let (deflation_ppm, r) = read_u32_le(p)?; p = r;
                let (initial_diff_bits, r) = read_u8(p)?; p = r;
                
                if initial_reward == 0 || max_supply == 0 { return Err(ContractError::Custom(1)); }
                if deflation_ppm > CXMIN_MAX_DEFLATION_PPM { return Err(ContractError::Custom(1)); }
                if initial_diff_bits < CXMIN_MIN_DIFF_BITS || initial_diff_bits > CXMIN_MAX_DIFF_BITS {
                    return Err(ContractError::Custom(1));
                }
                
                // Parse optional metatags if present
                let mut name = Vec::new();
                let mut ticker = Vec::new();
                let mut icon = Vec::new();
                
                // If there's more data, try to read metatags
                if !p.is_empty() {
                    // Read name
                    if p.len() >= 2 {
                        let (name_len, r) = read_u16_le(p)?; p = r;
                        if name_len > 0 && p.len() >= name_len as usize {
                            name.extend_from_slice(&p[..name_len as usize]);
                            p = &p[name_len as usize..];
                        }
                    }
                    
                    // Read ticker
                    if !p.is_empty() && p.len() >= 2 {
                        let (ticker_len, r) = read_u16_le(p)?; p = r;
                        if ticker_len > 0 && p.len() >= ticker_len as usize {
                            ticker.extend_from_slice(&p[..ticker_len as usize]);
                            p = &p[ticker_len as usize..];
                        }
                    }
                    
                    // Read icon
                    if !p.is_empty() && p.len() >= 2 {
                        let (icon_len, r) = read_u16_le(p)?; p = r;
                        if icon_len > 0 && p.len() >= icon_len as usize {
                            icon.extend_from_slice(&p[..icon_len as usize]);
                        }
                    }
                }
                
                // Check total metatag size
                let total_metatag_size = name.len() + ticker.len() + icon.len();
                if total_metatag_size > CXMIN_MAX_METATAG_SIZE {
                    return Err(ContractError::Custom(25)); // MetatagsTooLarge
                }

                // Optional decimals (1..=6), default 0 (whole tokens)
                let mut decimals: u8 = 0;
                if !p.is_empty() {
                    let (d, _r) = read_u8(p)?;
                    if d == 0 || d > 6 {
                        return Err(ContractError::Custom(5)); // InvalidParam
                    }
                    decimals = d;
                }
                
                let st = CxMinState {
                    admin,
                    paused: 0,
                    total_supply: 0,
                    max_supply,
                    reward_per_block: initial_reward,
                    initial_reward_per_block: initial_reward,
                    deflation_ppm,
                    last_deflation_height: ctx.block_height,
                    difficulty_bits: initial_diff_bits,
                    target_interval_blocks: CXMIN_TARGET_INTERVAL_BLOCKS,
                    last_reward_height: 0,
                    blocks_mined: 0,
                    balances: Vec::new(),
                    name,
                    ticker,
                    icon,
                    decimals,
                };
                st.encode()
            }
            // 1 mine(miner_address_hash, nonce)
            1 => {
                if data.len() != 32 + 8 { return Err(ContractError::InvalidState); }
                if state.is_empty() { return Err(ContractError::InvalidState); }
                // Decode state early and enforce finished/emission and block interval checks deterministically
                let st_pre = CxMinState::decode(state)?;
                if st_pre.total_supply >= st_pre.max_supply {
                    return Err(ContractError::Custom(21)); // EmissionFinished
                }
                if st_pre.blocks_mined > 0 && ctx.block_height < st_pre.last_reward_height.saturating_add(CXMIN_MIN_INTERVAL_BLOCKS) {
                    return Err(ContractError::Custom(22)); // MiningTooFast
                }
                let mut p = data;
                let (miner, r) = read_hash32(p)?; p = r;
                let (nonce, _) = read_u64_le(p)?;
                apply_mine_common(st_pre, miner, nonce, ctx, 250u64, true)
            }
            // 2 transfer(from, to, amount)
            2 => {
                if data.len() != 32 + 32 + 8 { return Err(ContractError::InvalidState); }
                let mut p = data;
                let (from, r) = read_hash32(p)?; p = r;
                let (to, r) = read_hash32(p)?; p = r;
                let (amount, _) = read_u64_le(p)?;
                if amount == 0 { return Err(ContractError::Custom(5)); }
                let mut st = CxMinState::decode(state)?;
                st.sub_balance(from, amount)?;
                st.add_balance(to, amount)?;
                st.encode()
            }
            // 3 burn(from, amount)
            3 => {
                if data.len() != 32 + 8 { return Err(ContractError::InvalidState); }
                let mut p = data;
                let (from, r) = read_hash32(p)?; p = r;
                let (amount, _) = read_u64_le(p)?;
                if amount == 0 { return Err(ContractError::Custom(5)); }
                let mut st = CxMinState::decode(state)?;
                st.sub_balance(from, amount)?;
                st.total_supply = st.total_supply.checked_sub(amount).ok_or(ContractError::Custom(11))?;
                st.encode()
            }
            // 4 pause(caller)
            4 => {
                if data.len() != 32 { return Err(ContractError::InvalidState); }
                let (caller, _) = read_hash32(data)?;
                let mut st = CxMinState::decode(state)?;
                if caller != st.admin { return Err(ContractError::Custom(2)); }
                st.paused = 1;
                st.encode()
            }
            // 5 unpause(caller)
            5 => {
                if data.len() != 32 { return Err(ContractError::InvalidState); }
                let (caller, _) = read_hash32(data)?;
                let mut st = CxMinState::decode(state)?;
                if caller != st.admin { return Err(ContractError::Custom(2)); }
                st.paused = 0;
                st.encode()
            }
            _ => Err(ContractError::InvalidAction),
        }
    }
}

impl Contract for CxMinBlake3Contract {
    fn apply(&self, state: &[u8], action_id: u16, data: &[u8], ctx: &BlockContext) -> Result<Vec<u8>, ContractError> {
        ensure_state_limit(state)?;
        match action_id {
            // 0 deploy(admin, initial_reward, max_supply, deflation_ppm, initial_difficulty_bits, [name, ticker, icon])
            0 => {
                if !state.is_empty() { return Err(ContractError::InvalidState); }
                if data.len() < 32 + 8 + 8 + 4 + 1 { return Err(ContractError::InvalidState); }
                let mut p = data;
                let (admin, r) = read_hash32(p)?; p = r;
                let (initial_reward, r) = read_u64_le(p)?; p = r;
                let (max_supply, r) = read_u64_le(p)?; p = r;
                let (deflation_ppm, r) = read_u32_le(p)?; p = r;
                let (initial_diff_bits, r) = read_u8(p)?; p = r;
                
                if initial_reward == 0 || max_supply == 0 { return Err(ContractError::Custom(1)); }
                if deflation_ppm > CXMIN_MAX_DEFLATION_PPM { return Err(ContractError::Custom(1)); }
                if initial_diff_bits < CXMIN_MIN_DIFF_BITS || initial_diff_bits > CXMIN_MAX_DIFF_BITS {
                    return Err(ContractError::Custom(1));
                }
                
                // Parse optional metatags if present
                let mut name = Vec::new();
                let mut ticker = Vec::new();
                let mut icon = Vec::new();
                
                // If there's more data, try to read metatags
                if !p.is_empty() {
                    // Read name
                    if p.len() >= 2 {
                        let (name_len, r) = read_u16_le(p)?; p = r;
                        if name_len > 0 && p.len() >= name_len as usize {
                            name.extend_from_slice(&p[..name_len as usize]);
                            p = &p[name_len as usize..];
                        }
                    }
                    
                    // Read ticker
                    if !p.is_empty() && p.len() >= 2 {
                        let (ticker_len, r) = read_u16_le(p)?; p = r;
                        if ticker_len > 0 && p.len() >= ticker_len as usize {
                            ticker.extend_from_slice(&p[..ticker_len as usize]);
                            p = &p[ticker_len as usize..];
                        }
                    }
                    
                    // Read icon
                    if !p.is_empty() && p.len() >= 2 {
                        let (icon_len, r) = read_u16_le(p)?; p = r;
                        if icon_len > 0 && p.len() >= icon_len as usize {
                            icon.extend_from_slice(&p[..icon_len as usize]);
                        }
                    }
                }
                
                // Check total metatag size
                let total_metatag_size = name.len() + ticker.len() + icon.len();
                if total_metatag_size > CXMIN_MAX_METATAG_SIZE {
                    return Err(ContractError::Custom(25)); // MetatagsTooLarge
                }

                // Optional decimals (1..=6), default 0 (whole tokens)
                let mut decimals: u8 = 0;
                if !p.is_empty() {
                    let (d, _r) = read_u8(p)?;
                    if d == 0 || d > 6 {
                        return Err(ContractError::Custom(5)); // InvalidParam
                    }
                    decimals = d;
                }
                
                let st = CxMinState {
                    admin,
                    paused: 0,
                    total_supply: 0,
                    max_supply,
                    reward_per_block: initial_reward,
                    initial_reward_per_block: initial_reward,
                    deflation_ppm,
                    last_deflation_height: ctx.block_height,
                    difficulty_bits: initial_diff_bits,
                    target_interval_blocks: CXMIN_TARGET_INTERVAL_BLOCKS,
                    last_reward_height: 0,
                    blocks_mined: 0,
                    balances: Vec::new(),
                    name,
                    ticker,
                    icon,
                    decimals,
                };
                st.encode()
            }
            1 => {
                if data.len() != 32 + 8 { return Err(ContractError::InvalidState); }
                if state.is_empty() { return Err(ContractError::InvalidState); }
                // Decode state early and enforce finished/emission and block interval checks deterministically
                let st_pre = CxMinState::decode(state)?;
                if st_pre.total_supply >= st_pre.max_supply {
                    return Err(ContractError::Custom(21)); // EmissionFinished
                }
                if st_pre.blocks_mined > 0 && ctx.block_height < st_pre.last_reward_height.saturating_add(CXMIN_MIN_INTERVAL_BLOCKS) {
                    return Err(ContractError::Custom(22)); // MiningTooFast
                }
                let mut p = data;
                let (miner, r) = read_hash32(p)?; p = r;
                let (nonce, _) = read_u64_le(p)?;
                apply_mine_common(st_pre, miner, nonce, ctx, 251u64, false)
            }
            2 => {
                if data.len() != 32 + 32 + 8 { return Err(ContractError::InvalidState); }
                let mut p = data;
                let (from, r) = read_hash32(p)?; p = r;
                let (to, r) = read_hash32(p)?; p = r;
                let (amount, _) = read_u64_le(p)?;
                if amount == 0 { return Err(ContractError::Custom(5)); }
                let mut st = CxMinState::decode(state)?;
                st.sub_balance(from, amount)?;
                st.add_balance(to, amount)?;
                st.encode()
            }
            3 => {
                if data.len() != 32 + 8 { return Err(ContractError::InvalidState); }
                let mut p = data;
                let (from, r) = read_hash32(p)?; p = r;
                let (amount, _) = read_u64_le(p)?;
                if amount == 0 { return Err(ContractError::Custom(5)); }
                let mut st = CxMinState::decode(state)?;
                st.sub_balance(from, amount)?;
                st.total_supply = st.total_supply.checked_sub(amount).ok_or(ContractError::Custom(11))?;
                st.encode()
            }
            4 => {
                if data.len() != 32 { return Err(ContractError::InvalidState); }
                let (caller, _) = read_hash32(data)?;
                let mut st = CxMinState::decode(state)?;
                if caller != st.admin { return Err(ContractError::Custom(2)); }
                st.paused = 1;
                st.encode()
            }
            5 => {
                if data.len() != 32 { return Err(ContractError::InvalidState); }
                let (caller, _) = read_hash32(data)?;
                let mut st = CxMinState::decode(state)?;
                if caller != st.admin { return Err(ContractError::Custom(2)); }
                st.paused = 0;
                st.encode()
            }
            _ => Err(ContractError::InvalidAction),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> BlockContext {
        BlockContext { block_height: 0, daa_score: 0, block_time: 0, tx_id: [0u8; 32], input_index: 0, auth_addr: [0u8; 32] }
    }
    fn addr(b: u8) -> AddressHash32 { [b; 32] }
    fn h32(b: u8) -> Hash32 { [b; 32] }

    // -------------------- CX-LP (380) --------------------

    #[test]
    fn cx_lp_deploy_redeploy_and_basic_ops() {
        let c = &CX_LP_CONTRACT;
        let admin = addr(9);
        // deploy
        let mut dep = Vec::new();
        dep.extend_from_slice(&h32(1)); dep.extend_from_slice(&h32(2));
        dep.extend_from_slice(&0u32.to_le_bytes()); dep.extend_from_slice(&admin);
        let st0 = c.apply(&[], 0, &dep, &ctx()).expect("deploy");
        // redeploy fails
        assert!(matches!(c.apply(&st0, 0, &dep, &ctx()), Err(ContractError::InvalidState)));

        // add 100/100
        let a = addr(1);
        let mut add = Vec::new();
        add.extend_from_slice(&a); add.extend_from_slice(&100u64.to_le_bytes()); add.extend_from_slice(&100u64.to_le_bytes());
        let st1 = c.apply(&st0, 1, &add, &ctx()).expect("add");

        // swap A->B 10
        let st2 = c.apply(&st1, 3, &10u64.to_le_bytes(), &ctx()).expect("swap a->b");
        let s2 = super::CxLpState::decode(&st2).unwrap();
        assert!(s2.reserve_a >= 110 && s2.reserve_b <= 100);

        // set_fee by admin
        let mut sf = Vec::new();
        sf.extend_from_slice(&admin); sf.extend_from_slice(&500u32.to_le_bytes());
        let st3 = c.apply(&st2, 5, &sf, &ctx()).expect("set fee");
        let s3 = super::CxLpState::decode(&st3).unwrap();
        assert_eq!(s3.fee_ppm, 500);
    }

    // -------------------- CX-Revenue (360) --------------------

    #[test]
    fn cx_revenue_deploy_deposit_claim() {
        let c = &CX_REVENUE_CONTRACT;
        let admin = addr(7);
        let a1 = addr(1); let a2 = addr(2);

        // deploy n=2
        let mut dep = Vec::new();
        dep.extend_from_slice(&2u16.to_le_bytes());
        dep.extend_from_slice(&a1); dep.extend_from_slice(&60u64.to_le_bytes());
        dep.extend_from_slice(&a2); dep.extend_from_slice(&40u64.to_le_bytes());
        dep.extend_from_slice(&admin);
        let st0 = c.apply(&[], 0, &dep, &ctx()).expect("deploy");

        // deposit 100 => a1:60, a2:40
        let st1 = c.apply(&st0, 1, &100u64.to_le_bytes(), &ctx()).expect("deposit");
        let s1 = super::CxRevenueState::decode(&st1).unwrap();
        assert_eq!(*s1.pending.get(&a1).unwrap_or(&0), 60);
        assert_eq!(*s1.pending.get(&a2).unwrap_or(&0), 40);

        // claim a1
        let mut cl = Vec::new(); cl.extend_from_slice(&a1);
        let st2 = c.apply(&st1, 2, &cl, &ctx()).expect("claim");
        let s2 = super::CxRevenueState::decode(&st2).unwrap();
        assert_eq!(*s2.pending.get(&a1).unwrap_or(&0), 0);
    }

    // -------------------- CX-Bridge (370) --------------------

    #[test]
    fn cx_bridge_deploy_pause_release_replay() {
        let c = &CX_BRIDGE_CONTRACT;
        let v1 = addr(1); let v2 = addr(2);

        // deploy with 2 validators threshold 2
        let mut dep = Vec::new();
        dep.extend_from_slice(&2u16.to_le_bytes());
        dep.extend_from_slice(&v1); dep.extend_from_slice(&v2);
        dep.extend_from_slice(&2u16.to_le_bytes());
        let st0 = c.apply(&[], 0, &dep, &ctx()).expect("deploy");

        // pause forbids release
        let st1 = c.apply(&st0, 5, &[], &ctx()).expect("pause");
        assert!(matches!(c.apply(&st1, 2, b"proof", &ctx()), Err(ContractError::Custom(9))));
        // unpause and release
        let st2 = c.apply(&st1, 6, &[], &ctx()).expect("unpause");
        let st3 = c.apply(&st2, 2, b"proof", &ctx()).expect("release");
        // replay protection
        assert!(matches!(c.apply(&st3, 2, b"proof", &ctx()), Err(ContractError::Custom(4))));
    }

    // -------------------- Additional Thorough Tests --------------------

    #[test]
    fn cx_lp_xyk_invariant_no_increase() {
        let c = &CX_LP_CONTRACT;
        let admin = addr(9);
        // deploy no fee
        let mut dep = Vec::new();
        dep.extend_from_slice(&h32(10)); dep.extend_from_slice(&h32(11));
        dep.extend_from_slice(&0u32.to_le_bytes()); dep.extend_from_slice(&admin);
        let st0 = c.apply(&[], 0, &dep, &ctx()).expect("deploy");

        // add 100/100
        let p = addr(1);
        let mut add = Vec::new();
        add.extend_from_slice(&p);
        add.extend_from_slice(&100u64.to_le_bytes());
        add.extend_from_slice(&100u64.to_le_bytes());
        let st1 = c.apply(&st0, 1, &add, &ctx()).expect("add");
        let s1 = super::CxLpState::decode(&st1).unwrap();
        let prod1 = (s1.reserve_a as u128) * (s1.reserve_b as u128);

        // swap A->B 10: product must not increase
        let st2 = c.apply(&st1, 3, &10u64.to_le_bytes(), &ctx()).expect("swap A->B");
        let s2 = super::CxLpState::decode(&st2).unwrap();
        let prod2 = (s2.reserve_a as u128) * (s2.reserve_b as u128);
        assert!(prod2 <= prod1, "XYK must not increase (A->B)");

        // swap B->A 5: product must not increase
        let st3 = c.apply(&st2, 4, &5u64.to_le_bytes(), &ctx()).expect("swap B->A");
        let s3 = super::CxLpState::decode(&st3).unwrap();
        let prod3 = (s3.reserve_a as u128) * (s3.reserve_b as u128);
        assert!(prod3 <= prod2, "XYK must not increase (B->A)");
    }

    #[test]
    fn cx_lp_mint_burn_proportionality_and_bounds() {
        let c = &CX_LP_CONTRACT;
        let admin = addr(7);

        // deploy no fee
        let mut dep = Vec::new();
        dep.extend_from_slice(&h32(20)); dep.extend_from_slice(&h32(21));
        dep.extend_from_slice(&0u32.to_le_bytes()); dep.extend_from_slice(&admin);
        let st0 = c.apply(&[], 0, &dep, &ctx()).expect("deploy");

        // add 100/100 => LP=100
        let p = addr(1);
        let mut add1 = Vec::new();
        add1.extend_from_slice(&p); add1.extend_from_slice(&100u64.to_le_bytes()); add1.extend_from_slice(&100u64.to_le_bytes());
        let st1 = c.apply(&st0, 1, &add1, &ctx()).expect("add1");
        let s1 = super::CxLpState::decode(&st1).unwrap();
        assert_eq!(s1.lp_total_supply, 100);

        // add 25/25 => LP=25
        let mut add2 = Vec::new();
        add2.extend_from_slice(&p); add2.extend_from_slice(&25u64.to_le_bytes()); add2.extend_from_slice(&25u64.to_le_bytes());
        let st2 = c.apply(&st1, 1, &add2, &ctx()).expect("add2");
        let s2 = super::CxLpState::decode(&st2).unwrap();
        assert_eq!(s2.lp_total_supply, 125);

        // remove 25 LP => should scale reserves back to 100/100
        let mut rem = Vec::new();
        rem.extend_from_slice(&p); rem.extend_from_slice(&25u64.to_le_bytes());
        let st3 = c.apply(&st2, 2, &rem, &ctx()).expect("remove");
        let s3 = super::CxLpState::decode(&st3).unwrap();
        assert_eq!(s3.reserve_a, 100);
        assert_eq!(s3.reserve_b, 100);
        assert_eq!(s3.lp_total_supply, 100);

        // set_fee bounds: > 1_000_000 should fail
        let mut bad_fee = Vec::new();
        bad_fee.extend_from_slice(&admin); bad_fee.extend_from_slice(&(1_000_001u32).to_le_bytes());
        let res = c.apply(&st3, 5, &bad_fee, &ctx());
        assert!(matches!(res, Err(ContractError::Custom(5))));
    }

    #[test]
    fn cx_revenue_set_shares_and_rounding() {
        let c = &CX_REVENUE_CONTRACT;
        let admin = addr(9);
        let a = addr(1);
        let b = addr(2);

        // deploy recipients A=1, B=1
        let mut dep = Vec::new();
        dep.extend_from_slice(&2u16.to_le_bytes());
        dep.extend_from_slice(&a); dep.extend_from_slice(&1u64.to_le_bytes());
        dep.extend_from_slice(&b); dep.extend_from_slice(&1u64.to_le_bytes());
        dep.extend_from_slice(&admin);
        let st0 = c.apply(&[], 0, &dep, &ctx()).expect("deploy");

        // deposit 1 -> both get floor(1*1/2)=0
        let st1 = c.apply(&st0, 1, &1u64.to_le_bytes(), &ctx()).expect("deposit1");
        let s1 = super::CxRevenueState::decode(&st1).unwrap();
        assert_eq!(*s1.pending.get(&a).unwrap_or(&0), 0);
        assert_eq!(*s1.pending.get(&b).unwrap_or(&0), 0);

        // deposit 3 -> both get 1
        let st2 = c.apply(&st1, 1, &3u64.to_le_bytes(), &ctx()).expect("deposit3");
        let s2 = super::CxRevenueState::decode(&st2).unwrap();
        assert_eq!(*s2.pending.get(&a).unwrap_or(&0), 1);
        assert_eq!(*s2.pending.get(&b).unwrap_or(&0), 1);

        // claim A
        let mut cl = Vec::new(); cl.extend_from_slice(&a);
        let st3 = c.apply(&st2, 2, &cl, &ctx()).expect("claim A");
        let s3 = super::CxRevenueState::decode(&st3).unwrap();
        assert_eq!(*s3.pending.get(&a).unwrap_or(&0), 0);

        // claim A again -> NoClaimable
        let res = c.apply(&st3, 2, &cl, &ctx());
        assert!(matches!(res, Err(ContractError::Custom(1))));

        // set_shares by admin to B=2 (single recipient) -> sorted+dedup + recompute
        let mut ss = Vec::new();
        ss.extend_from_slice(&admin);
        ss.extend_from_slice(&1u16.to_le_bytes());
        ss.extend_from_slice(&b); ss.extend_from_slice(&2u64.to_le_bytes());
        let st4 = c.apply(&st3, 3, &ss, &ctx()).expect("set_shares");
        let s4 = super::CxRevenueState::decode(&st4).unwrap();
        assert_eq!(s4.recipients.len(), 1);
        assert_eq!(s4.total_shares, 2);
    }

    #[test]
    fn cx_bridge_threshold_bounds_and_verify_no_mutation() {
        let c = &CX_BRIDGE_CONTRACT;
        let v1 = addr(1); let v2 = addr(2);

        // deploy 2 validators threshold 2
        let mut dep = Vec::new();
        dep.extend_from_slice(&2u16.to_le_bytes());
        dep.extend_from_slice(&v1); dep.extend_from_slice(&v2);
        dep.extend_from_slice(&2u16.to_le_bytes());
        let st0 = c.apply(&[], 0, &dep, &ctx()).expect("deploy");

        // verify_proof should not mutate state
        let st1 = c.apply(&st0, 3, b"abc", &ctx()).expect("verify");
        let s0 = super::CxBridgeState::decode(&st0).unwrap();
        let s1 = super::CxBridgeState::decode(&st1).unwrap();
        assert_eq!(s0.processed_proofs.len(), 0);
        assert_eq!(s1.processed_proofs.len(), 0);

        // pause and verify should fail
        let st_p = c.apply(&st0, 5, &[], &ctx()).expect("pause");
        let res = c.apply(&st_p, 3, b"abc", &ctx());
        assert!(matches!(res, Err(ContractError::Custom(9))));

        // unpause and set_validators with invalid threshold=0 -> error
        let st_u = c.apply(&st_p, 6, &[], &ctx()).expect("unpause");
        let mut sv_bad = Vec::new();
        sv_bad.extend_from_slice(&2u16.to_le_bytes());
        sv_bad.extend_from_slice(&v1); sv_bad.extend_from_slice(&v2);
        sv_bad.extend_from_slice(&0u16.to_le_bytes());
        let res2 = c.apply(&st_u, 4, &sv_bad, &ctx());
        assert!(matches!(res2, Err(ContractError::Custom(5))));
    }

    // -------------------- CX-MIN (250/251) --------------------

    fn find_nonce_sha3(state: &[u8], miner: AddressHash32, mut ctx_local: BlockContext) -> (Vec<u8>, u64) {
        let c = &CX_MIN_SHA3_CONTRACT;
        // Try a deterministic nonce range
        let mut nonce: u64 = 0;
        loop {
            let mut data = Vec::new();
            data.extend_from_slice(&miner);
            data.extend_from_slice(&nonce.to_le_bytes());
            if let Ok(new_st) = c.apply(state, 1, &data, &ctx_local) {
                return (new_st, nonce);
            }
            nonce = nonce.saturating_add(1);
            // bump height every 10000 trials to avoid pathological block interval lock (should not be needed on first mine)
            if nonce % 10_000 == 0 {
                ctx_local.block_height = ctx_local.block_height.saturating_add(1);
            }
        }
    }

    fn find_nonce_blake3(state: &[u8], miner: AddressHash32, mut ctx_local: BlockContext) -> (Vec<u8>, u64) {
        let c = &CX_MIN_BLAKE3_CONTRACT;
        let mut nonce: u64 = 0;
        loop {
            let mut data = Vec::new();
            data.extend_from_slice(&miner);
            data.extend_from_slice(&nonce.to_le_bytes());
            if let Ok(new_st) = c.apply(state, 1, &data, &ctx_local) {
                return (new_st, nonce);
            }
            nonce = nonce.saturating_add(1);
            if nonce % 10_000 == 0 {
                ctx_local.block_height = ctx_local.block_height.saturating_add(1);
            }
        }
    }

    #[test]
    fn cx_min_sha3_deploy_redeploy() {
        let c = &CX_MIN_SHA3_CONTRACT;
        let admin = addr(9);

        // deploy(admin, initial_reward=100, max_supply=1000, deflation_ppm=0, diff_bits=1)
        let mut dep = Vec::new();
        dep.extend_from_slice(&admin);
        dep.extend_from_slice(&100u64.to_le_bytes());
        dep.extend_from_slice(&1000u64.to_le_bytes());
        dep.extend_from_slice(&0u32.to_le_bytes());
        dep.push(1u8);
        let st = c.apply(&[], 0, &dep, &ctx()).expect("deploy");

        // redeploy should fail
        let res = c.apply(&st, 0, &dep, &ctx());
        assert!(matches!(res, Err(ContractError::InvalidState)));
    }

    #[test]
    fn cx_min_sha3_mine_valid_and_lockout() {
        let c = &CX_MIN_SHA3_CONTRACT;
        let admin = addr(7);
        let miner = addr(1);

        // deploy with low difficulty and no deflation
        let mut dep = Vec::new();
        dep.extend_from_slice(&admin);
        dep.extend_from_slice(&10u64.to_le_bytes());
        dep.extend_from_slice(&1000u64.to_le_bytes());
        dep.extend_from_slice(&0u32.to_le_bytes());
        dep.push(1u8);
        let st0 = c.apply(&[], 0, &dep, &ctx()).expect("deploy");
        let mut local_ctx = ctx();

        // mine once
        let (st1, _nonce) = find_nonce_sha3(&st0, miner, local_ctx.clone());
        let s1 = super::CxMinState::decode(&st1).unwrap();
        assert_eq!(s1.total_supply, 10);
        assert_eq!(s1.blocks_mined, 1);
        assert_eq!(*s1.balances.iter().find(|(a,_)| a == &miner).map(|(_,v)| v).unwrap_or(&0), 10);

        // mining again too fast (<30 blocks) should fail
        let mut data = Vec::new();
        data.extend_from_slice(&miner);
        data.extend_from_slice(&0u64.to_le_bytes());
        let res_fast = c.apply(&st1, 1, &data, &local_ctx);
        assert!(matches!(res_fast, Err(ContractError::Custom(22)))); // MiningTooFast

        // after 60 blocks, mining allowed and difficulty auto-adjusts
        local_ctx.block_height = s1.last_reward_height.saturating_add(60);
        let (st2, _n2) = find_nonce_sha3(&st1, miner, local_ctx.clone());
        let s2 = super::CxMinState::decode(&st2).unwrap();
        assert_eq!(s2.total_supply, 20);
        assert_eq!(s2.blocks_mined, 2);
        // difficulty bits either stays or adjusts by +/-1 according to block interval; just ensure range
        assert!(s2.difficulty_bits >= CXMIN_MIN_DIFF_BITS && s2.difficulty_bits <= CXMIN_MAX_DIFF_BITS);
    }

    #[test]
    fn cx_min_sha3_pause_unpause() {
        let c = &CX_MIN_SHA3_CONTRACT;
        let admin = addr(5);
        let miner = addr(3);

        // deploy
        let mut dep = Vec::new();
        dep.extend_from_slice(&admin);
        dep.extend_from_slice(&10u64.to_le_bytes());
        dep.extend_from_slice(&1000u64.to_le_bytes());
        dep.extend_from_slice(&0u32.to_le_bytes());
        dep.push(1u8);
        let st0 = c.apply(&[], 0, &dep, &ctx()).unwrap();

        // pause by admin
        let st1 = c.apply(&st0, 4, &admin, &ctx()).unwrap();

        // mine should fail with Paused
        let mut data = Vec::new();
        data.extend_from_slice(&miner);
        data.extend_from_slice(&0u64.to_le_bytes());
        let res = c.apply(&st1, 1, &data, &ctx());
        assert!(matches!(res, Err(ContractError::Custom(20))));

        // unpause by admin
        let st2 = c.apply(&st1, 5, &admin, &ctx()).unwrap();
        // should be able to mine again eventually
        let (_st3, _n) = find_nonce_sha3(&st2, miner, ctx());
    }

    #[test]
    fn cx_min_sha3_transfer_burn() {
        let c = &CX_MIN_SHA3_CONTRACT;
        let admin = addr(7);
        let a = addr(1);
        let b = addr(2);

        // deploy with reward=10, max=100
        let mut dep = Vec::new();
        dep.extend_from_slice(&admin);
        dep.extend_from_slice(&10u64.to_le_bytes());
        dep.extend_from_slice(&100u64.to_le_bytes());
        dep.extend_from_slice(&0u32.to_le_bytes());
        dep.push(1u8);
        let st0 = c.apply(&[], 0, &dep, &ctx()).unwrap();

        // mine to give A some tokens
        let (st1, _) = find_nonce_sha3(&st0, a, ctx());
        let s1 = super::CxMinState::decode(&st1).unwrap();
        assert_eq!(*s1.balances.iter().find(|(ad,_)| ad==&a).map(|(_,v)| v).unwrap_or(&0), 10);

        // transfer 6 from A to B
        let mut tr = Vec::new();
        tr.extend_from_slice(&a); tr.extend_from_slice(&b); tr.extend_from_slice(&6u64.to_le_bytes());
        let st2 = c.apply(&st1, 2, &tr, &ctx()).unwrap();
        let s2 = super::CxMinState::decode(&st2).unwrap();
        assert_eq!(*s2.balances.iter().find(|(ad,_)| ad==&a).map(|(_,v)| v).unwrap_or(&0), 4);
        assert_eq!(*s2.balances.iter().find(|(ad,_)| ad==&b).map(|(_,v)| v).unwrap_or(&0), 6);

        // burn 4 from B -> insufficient
        let mut burn_bad = Vec::new();
        burn_bad.extend_from_slice(&b); burn_bad.extend_from_slice(&7u64.to_le_bytes());
        let res = c.apply(&st2, 3, &burn_bad, &ctx());
        assert!(matches!(res, Err(ContractError::Custom(1))));

        // burn 4 from B success
        let mut burn_ok = Vec::new();
        burn_ok.extend_from_slice(&b); burn_ok.extend_from_slice(&4u64.to_le_bytes());
        let st3 = c.apply(&st2, 3, &burn_ok, &ctx()).unwrap();
        let s3 = super::CxMinState::decode(&st3).unwrap();
        assert_eq!(*s3.balances.iter().find(|(ad,_)| ad==&b).map(|(_,v)| v).unwrap_or(&0), 2);
        assert_eq!(s3.total_supply, 10 - 4);
    }

    #[test]
    fn cx_min_sha3_deflation_and_max_supply() {
        let c = &CX_MIN_SHA3_CONTRACT;
        let admin = addr(7);
        let miner = addr(1);

        // deflation 10% per month
        let mut dep = Vec::new();
        dep.extend_from_slice(&admin);
        dep.extend_from_slice(&100u64.to_le_bytes());     // initial reward
        dep.extend_from_slice(&1000u64.to_le_bytes());    // max supply
        dep.extend_from_slice(&100_000u32.to_le_bytes()); // 10%
        dep.push(1u8);
        let mut local_ctx = ctx();
        local_ctx.block_height = 1_000_000;
        let st0 = c.apply(&[], 0, &dep, &local_ctx).unwrap();

        // mine once at t
        let (st1, _) = find_nonce_sha3(&st0, miner, local_ctx.clone());
        let s1 = super::CxMinState::decode(&st1).unwrap();
        assert_eq!(s1.reward_per_block, 100);

        // advance > 1 month + 60 blocks to allow mining + deflation
        local_ctx.block_height = s1.last_reward_height + CXMIN_MONTH_BLOCKS + 60;
        let (st2, _) = find_nonce_sha3(&st1, miner, local_ctx.clone());
        let s2 = super::CxMinState::decode(&st2).unwrap();
        // reward should have deflated: 100 * (1-0.1) = 90
        assert_eq!(s2.reward_per_block, 90);

        // set max_supply edge: mine until near cap
        // For block height, just ensure remaining cap honored:
        let mut near_cap = s2.clone();
        near_cap.total_supply = near_cap.max_supply - 50;
        let st_near = near_cap.encode().unwrap();
        local_ctx.block_height += 60;
        let (st3, _) = find_nonce_sha3(&st_near, miner, local_ctx.clone());
        let s3 = super::CxMinState::decode(&st3).unwrap();
        // reward granted at most remaining (<= 50)
        assert!(s3.total_supply <= near_cap.max_supply);

        // if total_supply == max_supply => EmissionFinished
        let mut at_cap = s3.clone();
        at_cap.total_supply = at_cap.max_supply;
        let st_cap = at_cap.encode().unwrap();
        let mut data = Vec::new();
        data.extend_from_slice(&miner);
        data.extend_from_slice(&0u64.to_le_bytes());
        let res = c.apply(&st_cap, 1, &data, &local_ctx);
        assert!(matches!(res, Err(ContractError::Custom(21))));
    }

    #[test]
    fn cx_min_blake3_basic_mine() {
        let c = &CX_MIN_BLAKE3_CONTRACT;
        let admin = addr(9);
        let miner = addr(2);

        // deploy
        let mut dep = Vec::new();
        dep.extend_from_slice(&admin);
        dep.extend_from_slice(&10u64.to_le_bytes());
        dep.extend_from_slice(&100u64.to_le_bytes());
        dep.extend_from_slice(&0u32.to_le_bytes());
        dep.push(1u8);
        let st0 = c.apply(&[], 0, &dep, &ctx()).unwrap();

        // mine
        let (st1, _) = find_nonce_blake3(&st0, miner, ctx());
        let s1 = super::CxMinState::decode(&st1).unwrap();
        assert_eq!(s1.total_supply, 10);
        assert_eq!(s1.blocks_mined, 1);
    }

    // -------------------- Additional Thorough Coverage --------------------

    #[test]
    fn cx_min_sha3_deflation_to_zero_reward() {
        let c = &CX_MIN_SHA3_CONTRACT;
        let admin = addr(7);
        let miner = addr(1);

        // Deploy with 100% monthly deflation so reward becomes 0 after >=1 month
        let mut dep = Vec::new();
        dep.extend_from_slice(&admin);
        dep.extend_from_slice(&100u64.to_le_bytes());     // initial reward
        dep.extend_from_slice(&1_000_000u64.to_le_bytes());// max supply
        dep.extend_from_slice(&1_000_000u32.to_le_bytes());// 100% deflation
        dep.push(1u8);
        let mut ctx0 = ctx();
        ctx0.block_height = 1_000_000;
        let st0 = c.apply(&[], 0, &dep, &ctx0).expect("deploy");

        // Try to mine after > 1 month: deflation should zero-out reward and Mining should fail with RewardZero (24)
        let mut ctx1 = ctx0.clone();
        ctx1.block_height = ctx0.block_height + CXMIN_MONTH_BLOCKS + 1; // 30 days + 1 block
        let mut data = Vec::new();
        data.extend_from_slice(&miner);
        data.extend_from_slice(&0u64.to_le_bytes());
        let res = c.apply(&st0, 1, &data, &ctx1);
        assert!(matches!(res, Err(ContractError::Custom(24)))); // RewardZero
    }

    #[test]
    fn cx_min_sha3_near_cap_then_finish() {
        let c = &CX_MIN_SHA3_CONTRACT;
        let admin = addr(7);
        let miner = addr(1);

        // Deploy with small reward
        let mut dep = Vec::new();
        dep.extend_from_slice(&admin);
        dep.extend_from_slice(&10u64.to_le_bytes());       // reward
        dep.extend_from_slice(&1000u64.to_le_bytes());     // max supply
        dep.extend_from_slice(&0u32.to_le_bytes());        // deflation 0
        dep.push(1u8);
        let mut ctx0 = ctx();
        ctx0.block_height = 10;
        let st0 = c.apply(&[], 0, &dep, &ctx0).unwrap();

        // Set state near cap: remaining = 3
        let mut near = super::CxMinState::decode(&st0).unwrap();
        near.total_supply = near.max_supply - 3;
        let st_near = near.encode().unwrap();

        // Mine once => grant remaining (3), reach cap
        let mut ctx1 = ctx0.clone();
        ctx1.block_height += 60;
        let (st1, _n1) = find_nonce_sha3(&st_near, miner, ctx1.clone());
        let s1 = super::CxMinState::decode(&st1).unwrap();
        assert_eq!(s1.total_supply, s1.max_supply);

        // Next attempt must fail with EmissionFinished (21)
        let mut ctx2 = ctx1.clone();
        ctx2.block_height += 60;
        let mut data2 = Vec::new();
        data2.extend_from_slice(&miner);
        data2.extend_from_slice(&0u64.to_le_bytes());
        let res2 = c.apply(&st1, 1, &data2, &ctx2);
        assert!(matches!(res2, Err(ContractError::Custom(21))));
    }

    #[test]
    fn cx_min_roundtrip_many_balances() {
        // Build synthetic state with many balances and ensure encode/decode idempotence and pruning of zeros.
        let mut st = super::CxMinState {
            admin: addr(9),
            paused: 0,
            total_supply: 0,
            max_supply: 1_000_000,
            reward_per_block: 10,
            initial_reward_per_block: 10,
            deflation_ppm: 0,
            last_deflation_height: 0,
            difficulty_bits: 1,
            target_interval_blocks: 60,
            last_reward_height: 0,
            blocks_mined: 0,
            balances: Vec::new(),
            name: Vec::new(),
            ticker: Vec::new(),
            icon: Vec::new(),
            decimals: 0,
        };
        // Add >100 unique positive balances and some zero balances that should be pruned
        for i in 0..120u8 {
            st.balances.push(([i; 32], 1));
        }
        st.balances.push(([200; 32], 0)); // zero should be pruned
        let enc1 = st.encode().expect("encode within size");
        let st2 = super::CxMinState::decode(&enc1).expect("decode");
        // Re-encode and compare exact bytes (canonical)
        let enc2 = st2.encode().expect("re-encode");
        assert_eq!(enc1, enc2);
        // Ensure zero entry pruned
        assert!(st2.balances.iter().find(|(a, _)| a == &[200; 32]).is_none());
    }

    #[test]
    fn cx_lp_invalid_zero_reserve_swap_and_insufficient_remove() {
        let c = &CX_LP_CONTRACT;
        let admin = addr(8);
        // Deploy with fee=0
        let mut dep = Vec::new();
        dep.extend_from_slice(&h32(1)); dep.extend_from_slice(&h32(2));
        dep.extend_from_slice(&0u32.to_le_bytes()); dep.extend_from_slice(&admin);
        let st0 = c.apply(&[], 0, &dep, &ctx()).unwrap();

        // Swap with zero reserves should fail
        let res = c.apply(&st0, 3, &10u64.to_le_bytes(), &ctx());
        assert!(matches!(res, Err(ContractError::Custom(5))));

        // Add liquidity by provider A
        let a = addr(1);
        let mut add = Vec::new();
        add.extend_from_slice(&a);
        add.extend_from_slice(&100u64.to_le_bytes());
        add.extend_from_slice(&100u64.to_le_bytes());
        let st1 = c.apply(&st0, 1, &add, &ctx()).unwrap();

        // Remove liquidity by provider B with no LP: should fail InsufficientBalance (Custom(1))
        let b = addr(2);
        let mut rem = Vec::new();
        rem.extend_from_slice(&b);
        rem.extend_from_slice(&10u64.to_le_bytes());
        let res2 = c.apply(&st1, 2, &rem, &ctx());
        assert!(matches!(res2, Err(ContractError::Custom(1))));
    }

    #[test]
    fn cx_lp_fee_ppm_extremes() {
        let c = &CX_LP_CONTRACT;
        let admin = addr(8);
        // Deploy with fee=0
        let mut dep = Vec::new();
        dep.extend_from_slice(&h32(3)); dep.extend_from_slice(&h32(4));
        dep.extend_from_slice(&0u32.to_le_bytes()); dep.extend_from_slice(&admin);
        let st0 = c.apply(&[], 0, &dep, &ctx()).unwrap();

        // set_fee to max allowed 1_000_000 should succeed
        let mut sf_ok = Vec::new();
        sf_ok.extend_from_slice(&admin); sf_ok.extend_from_slice(&1_000_000u32.to_le_bytes());
        let st1 = c.apply(&st0, 5, &sf_ok, &ctx()).expect("set_fee max ok");
        let s1 = super::CxLpState::decode(&st1).unwrap();
        assert_eq!(s1.fee_ppm, 1_000_000);

        // set_fee > max should fail
        let mut sf_bad = Vec::new();
        sf_bad.extend_from_slice(&admin); sf_bad.extend_from_slice(&(1_000_001u32).to_le_bytes());
        let res = c.apply(&st1, 5, &sf_bad, &ctx());
        assert!(matches!(res, Err(ContractError::Custom(5))));
    }

    #[test]
    fn cx_revenue_redeploy_reject_pruning_and_size_growth() {
        let c = &CX_REVENUE_CONTRACT;
        let admin = addr(7);

        // Deploy with one zero-share recipient that should be pruned
        let a = addr(1);
        let z = addr(2);
        let mut dep = Vec::new();
        dep.extend_from_slice(&2u16.to_le_bytes());
        dep.extend_from_slice(&a); dep.extend_from_slice(&10u64.to_le_bytes());
        dep.extend_from_slice(&z); dep.extend_from_slice(&0u64.to_le_bytes()); // zero share -> pruned
        dep.extend_from_slice(&admin);
        let st0 = c.apply(&[], 0, &dep, &ctx()).expect("deploy");
        let s0 = super::CxRevenueState::decode(&st0).unwrap();
        assert_eq!(s0.recipients.len(), 1);

        // Redeploy should be rejected
        let res_redeploy = c.apply(&st0, 0, &dep, &ctx());
        assert!(matches!(res_redeploy, Err(ContractError::InvalidState)));

        // Invalid action id should be rejected
        let res_invalid = c.apply(&st0, 9, &[], &ctx());
        assert!(matches!(res_invalid, Err(ContractError::InvalidAction)));

        // State growth to exceed 8KB via set_shares with many recipients
        // Build a large set_shares payload
        let mut ctx_local = ctx();
        let mut payload = Vec::new();
        payload.extend_from_slice(&admin);
        let n: u16 = 512; // likely large enough to exceed 8KB
        payload.extend_from_slice(&n.to_le_bytes());
        for i in 0..(n as usize) {
            let addr_i = [i as u8; 32];
            payload.extend_from_slice(&addr_i);
            payload.extend_from_slice(&1u64.to_le_bytes());
        }
        let res_big = c.apply(&st0, 3, &payload, &ctx_local);
        assert!(matches!(res_big, Err(ContractError::StateTooLarge)));
    }

    #[test]
    fn cx_bridge_processed_proofs_growth_and_pause_gating() {
        let c = &CX_BRIDGE_CONTRACT;
        let v1 = addr(1); let v2 = addr(2);

        // Deploy with threshold 2
        let mut dep = Vec::new();
        dep.extend_from_slice(&2u16.to_le_bytes());
        dep.extend_from_slice(&v1); dep.extend_from_slice(&v2);
        dep.extend_from_slice(&2u16.to_le_bytes());
        let mut st = c.apply(&[], 0, &dep, &ctx()).expect("deploy");

        // Add a proof and then attempt replay -> AlreadyProcessed (Custom(4))
        st = c.apply(&st, 2, b"proof-1", &ctx()).expect("release p1");
        let res_replay = c.apply(&st, 2, b"proof-1", &ctx());
        assert!(matches!(res_replay, Err(ContractError::Custom(4))));

        // Grow processed_proofs until StateTooLarge
        let mut saw_too_large = false;
        for i in 0..2000u32 {
            let pr = format!("proof-{}", i+2);
            match c.apply(&st, 2, pr.as_bytes(), &ctx()) {
                Ok(new_st) => { st = new_st; }
                Err(ContractError::StateTooLarge) => { saw_too_large = true; break; }
                Err(e) => panic!("unexpected error while growing proofs: {:?}", e),
            }
        }
        assert!(saw_too_large, "expected to hit StateTooLarge while growing processed_proofs");

        // Pause gating sequence: pause forbids all except pause/unpause
        let st_p = c.apply(&st, 5, &[], &ctx()).expect("pause");
        assert!(matches!(c.apply(&st_p, 1, &[0u8; 32+8+32+4], &ctx()), Err(ContractError::Custom(9)))); // lock
        assert!(matches!(c.apply(&st_p, 2, b"x", &ctx()), Err(ContractError::Custom(9)))); // release
        assert!(matches!(c.apply(&st_p, 3, b"x", &ctx()), Err(ContractError::Custom(9)))); // verify
        // set_validators while paused -> forbidden
        let mut sv = Vec::new();
        sv.extend_from_slice(&2u16.to_le_bytes());
        sv.extend_from_slice(&v1); sv.extend_from_slice(&v2);
        sv.extend_from_slice(&2u16.to_le_bytes());
        assert!(matches!(c.apply(&st_p, 4, &sv, &ctx()), Err(ContractError::Custom(9))));
    }
}
