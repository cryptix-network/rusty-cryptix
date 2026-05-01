use blake2b_simd::Params as Blake2bParams;
use cryptix_consensus_core::BlockHasher;
use cryptix_consensus_core::{constants::MAX_SOMPI, tx::TransactionOutpoint};
use cryptix_database::prelude::CachePolicy;
use cryptix_database::prelude::StoreError;
use cryptix_database::prelude::DB;
use cryptix_database::prelude::{BatchDbWriter, CachedDbAccess, DirectDbWriter};
use cryptix_database::registry::DatabaseStorePrefixes;
use cryptix_hashes::Hash;
use cryptix_utils::mem_size::MemSizeEstimator;
use rocksdb::WriteBatch;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::mem::size_of;
use std::sync::Arc;

const ATOMIC_CONSENSUS_STATE_MAGIC: &[u8; 8] = b"CATCS004";
const ATOMIC_CONSENSUS_STATE_HASH_DOMAIN: &[u8] = b"cryptix-atomic-consensus-state-v4";
const ATOMIC_STATE_COMMITMENT_DOMAIN: &[u8] = b"cryptix-utxo-atomic-state-commitment-v1";
pub const ATOMIC_CURRENT_TOKEN_VERSION: u8 = 1;
pub const ATOMIC_CURRENT_LIQUIDITY_CURVE_VERSION: u8 = 1;
pub const ATOMIC_LIQUIDITY_CURVE_MODE_BASIC: u8 = 0;
pub const ATOMIC_LIQUIDITY_CURVE_MODE_AGGRESSIVE: u8 = 1;
pub const ATOMIC_LIQUIDITY_CURVE_MODE_INDIVIDUAL: u8 = 2;
pub const ATOMIC_DEFAULT_LIQUIDITY_CURVE_MODE: u8 = ATOMIC_LIQUIDITY_CURVE_MODE_BASIC;
const ATOMIC_INDIVIDUAL_MIN_VIRTUAL_CPAY_RESERVES_SOMPI: u64 = 100_000_000_000_000;
const ATOMIC_INDIVIDUAL_MAX_VIRTUAL_CPAY_RESERVES_SOMPI: u64 = 800_000_000_000_000;
const ATOMIC_INDIVIDUAL_VIRTUAL_CPAY_STEP_SOMPI: u64 = 10_000_000_000_000;
const ATOMIC_INDIVIDUAL_MIN_VIRTUAL_TOKEN_MULTIPLIER_BPS: u16 = 10_100;
const ATOMIC_INDIVIDUAL_MAX_VIRTUAL_TOKEN_MULTIPLIER_BPS: u16 = 20_000;
const ATOMIC_INDIVIDUAL_VIRTUAL_TOKEN_MULTIPLIER_STEP_BPS: u16 = 100;
const ATOMIC_MAX_TOKEN_VERSION: u8 = 99;
const ATOMIC_MAX_LIQUIDITY_CURVE_VERSION: u8 = 99;
const ATOMIC_OWNER_DOMAIN: &[u8] = b"CAT_OWNER_V2";
const OWNER_AUTH_SCHEME_PUBKEY: u8 = 0;
const OWNER_AUTH_SCHEME_PUBKEY_ECDSA: u8 = 1;
const OWNER_AUTH_SCHEME_SCRIPT_HASH: u8 = 2;
const MAX_ATOMIC_LIQUIDITY_FEE_RECIPIENTS: usize = 2;
const MIN_ATOMIC_LIQUIDITY_FEE_BPS: u16 = 10;
const MAX_ATOMIC_LIQUIDITY_FEE_BPS: u16 = 1000;
const MAX_ATOMIC_PLATFORM_TAG_LEN: usize = 50;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AtomicBalanceKey {
    pub asset_id: [u8; 32],
    pub owner_id: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AtomicSupplyMode {
    Uncapped,
    Capped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AtomicAssetClass {
    #[default]
    Standard,
    Liquidity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomicLiquidityFeeRecipientState {
    pub owner_id: [u8; 32],
    pub address_version: u8,
    pub address_payload: Vec<u8>,
    pub unclaimed_sompi: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomicLiquidityPoolState {
    pub pool_nonce: u64,
    #[serde(default = "default_atomic_liquidity_curve_version")]
    pub curve_version: u8,
    #[serde(default = "default_atomic_liquidity_curve_mode")]
    pub curve_mode: u8,
    #[serde(default)]
    pub individual_virtual_cpay_reserves_sompi: u64,
    #[serde(default)]
    pub individual_virtual_token_multiplier_bps: u16,
    pub real_cpay_reserves_sompi: u64,
    pub real_token_reserves: u128,
    pub virtual_cpay_reserves_sompi: u64,
    pub virtual_token_reserves: u128,
    pub unclaimed_fee_total_sompi: u64,
    pub fee_bps: u16,
    pub fee_recipients: Vec<AtomicLiquidityFeeRecipientState>,
    pub vault_outpoint: TransactionOutpoint,
    pub vault_value_sompi: u64,
    #[serde(default)]
    pub unlock_target_sompi: u64,
    #[serde(default = "default_atomic_liquidity_unlocked")]
    pub unlocked: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomicAssetState {
    #[serde(default)]
    pub asset_class: AtomicAssetClass,
    #[serde(default = "default_atomic_token_version")]
    pub token_version: u8,
    pub mint_authority_owner_id: [u8; 32],
    pub supply_mode: AtomicSupplyMode,
    pub max_supply: u128,
    pub total_supply: u128,
    #[serde(default)]
    pub platform_tag: Vec<u8>,
    #[serde(default)]
    pub liquidity: Option<AtomicLiquidityPoolState>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AtomicConsensusState {
    #[serde(default)]
    pub next_nonces: HashMap<[u8; 32], u64>,
    #[serde(default)]
    pub assets: HashMap<[u8; 32], AtomicAssetState>,
    #[serde(default)]
    pub balances: HashMap<AtomicBalanceKey, u128>,
    #[serde(default)]
    pub anchor_counts: HashMap<[u8; 32], u64>,
    #[serde(default)]
    pub liquidity_vault_outpoints: HashMap<TransactionOutpoint, [u8; 32]>,
}

fn default_atomic_liquidity_unlocked() -> bool {
    true
}

fn default_atomic_token_version() -> u8 {
    ATOMIC_CURRENT_TOKEN_VERSION
}

fn default_atomic_liquidity_curve_version() -> u8 {
    ATOMIC_CURRENT_LIQUIDITY_CURVE_VERSION
}

fn default_atomic_liquidity_curve_mode() -> u8 {
    ATOMIC_DEFAULT_LIQUIDITY_CURVE_MODE
}

impl AtomicConsensusState {
    pub fn rebuild_liquidity_vault_outpoint_index(&mut self) {
        self.liquidity_vault_outpoints.clear();
        for (asset_id, asset) in self.assets.iter() {
            let Some(pool) = asset.liquidity.as_ref() else {
                continue;
            };
            if !matches!(asset.asset_class, AtomicAssetClass::Liquidity) {
                continue;
            }
            self.liquidity_vault_outpoints.insert(pool.vault_outpoint, *asset_id);
        }
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(ATOMIC_CONSENSUS_STATE_MAGIC);

        let mut nonces: Vec<_> = self.next_nonces.iter().collect();
        nonces.sort_unstable_by(|a, b| a.0.cmp(b.0));
        write_len(&mut out, nonces.len());
        for (owner_id, nonce) in nonces {
            out.extend_from_slice(owner_id);
            write_u64(&mut out, *nonce);
        }

        let mut assets: Vec<_> = self.assets.iter().collect();
        assets.sort_unstable_by(|a, b| a.0.cmp(b.0));
        write_len(&mut out, assets.len());
        for (asset_id, asset) in assets {
            out.extend_from_slice(asset_id);
            write_asset(&mut out, asset);
        }

        let mut balances: Vec<_> = self.balances.iter().collect();
        balances.sort_unstable_by(|a, b| a.0.asset_id.cmp(&b.0.asset_id).then(a.0.owner_id.cmp(&b.0.owner_id)));
        write_len(&mut out, balances.len());
        for (key, amount) in balances {
            out.extend_from_slice(&key.asset_id);
            out.extend_from_slice(&key.owner_id);
            write_u128(&mut out, *amount);
        }

        let mut anchor_counts: Vec<_> = self.anchor_counts.iter().collect();
        anchor_counts.sort_unstable_by(|a, b| a.0.cmp(b.0));
        write_len(&mut out, anchor_counts.len());
        for (owner_id, count) in anchor_counts {
            out.extend_from_slice(owner_id);
            write_u64(&mut out, *count);
        }

        out
    }

    pub fn canonical_hash(&self) -> [u8; 32] {
        Self::hash_canonical_bytes(&self.to_canonical_bytes())
    }

    pub fn hash_canonical_bytes(bytes: &[u8]) -> [u8; 32] {
        let mut hasher = Blake2bParams::new().hash_length(32).to_state();
        hasher.update(ATOMIC_CONSENSUS_STATE_HASH_DOMAIN);
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_bytes());
        out
    }

    pub fn header_commitment(utxo_commitment: Hash, atomic_state_hash: [u8; 32], payload_hf_active: bool) -> Hash {
        if !payload_hf_active {
            return utxo_commitment;
        }

        let mut hasher = Blake2bParams::new().hash_length(32).to_state();
        hasher.update(ATOMIC_STATE_COMMITMENT_DOMAIN);
        hasher.update(&utxo_commitment.as_bytes());
        hasher.update(&atomic_state_hash);
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_bytes());
        Hash::from_bytes(out)
    }

    pub fn header_commitment_for_state(&self, utxo_commitment: Hash, payload_hf_active: bool) -> Hash {
        Self::header_commitment(utxo_commitment, self.canonical_hash(), payload_hf_active)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        let mut reader = AtomicStateReader::new(bytes);
        let magic = reader.read_bytes(ATOMIC_CONSENSUS_STATE_MAGIC.len())?;
        if magic != ATOMIC_CONSENSUS_STATE_MAGIC {
            return Err("invalid atomic consensus state magic".to_string());
        }

        let mut next_nonces = HashMap::new();
        let nonce_len = reader.read_len()?;
        for _ in 0..nonce_len {
            let owner_id = reader.read_32()?;
            let nonce = reader.read_u64()?;
            if next_nonces.insert(owner_id, nonce).is_some() {
                return Err("duplicate atomic nonce owner id".to_string());
            }
        }

        let mut assets = HashMap::new();
        let asset_len = reader.read_len()?;
        for _ in 0..asset_len {
            let asset_id = reader.read_32()?;
            let asset = reader.read_asset()?;
            if assets.insert(asset_id, asset).is_some() {
                return Err("duplicate atomic asset id".to_string());
            }
        }

        let mut balances = HashMap::new();
        let balance_len = reader.read_len()?;
        for _ in 0..balance_len {
            let key = AtomicBalanceKey { asset_id: reader.read_32()?, owner_id: reader.read_32()? };
            let amount = reader.read_u128()?;
            if balances.insert(key, amount).is_some() {
                return Err("duplicate atomic balance key".to_string());
            }
        }

        let mut anchor_counts = HashMap::new();
        let anchor_len = reader.read_len()?;
        for _ in 0..anchor_len {
            let owner_id = reader.read_32()?;
            let count = reader.read_u64()?;
            if anchor_counts.insert(owner_id, count).is_some() {
                return Err("duplicate atomic anchor owner id".to_string());
            }
        }

        reader.finish()?;

        let mut state = Self { next_nonces, assets, balances, anchor_counts, liquidity_vault_outpoints: Default::default() };
        state.rebuild_liquidity_vault_outpoint_index();
        Ok(state)
    }

    pub fn validate_normalized(&self) -> Result<(), String> {
        for (owner_id, nonce) in self.next_nonces.iter() {
            if *nonce < 2 {
                return Err(format!("atomic nonce for owner `{}` is not normalized", faster_hex::hex_string(owner_id)));
            }
        }

        for (owner_id, count) in self.anchor_counts.iter() {
            if *count == 0 {
                return Err(format!("zero atomic anchor count for owner `{}`", faster_hex::hex_string(owner_id)));
            }
        }

        let mut balance_totals: HashMap<[u8; 32], u128> = HashMap::new();
        for (key, amount) in self.balances.iter() {
            if *amount == 0 {
                return Err(format!(
                    "zero atomic balance for asset `{}` owner `{}`",
                    faster_hex::hex_string(&key.asset_id),
                    faster_hex::hex_string(&key.owner_id)
                ));
            }
            if !self.assets.contains_key(&key.asset_id) {
                return Err(format!("atomic balance references unknown asset `{}`", faster_hex::hex_string(&key.asset_id)));
            }
            let total = balance_totals.entry(key.asset_id).or_insert(0);
            *total = total
                .checked_add(*amount)
                .ok_or_else(|| format!("balance total overflow for asset `{}`", faster_hex::hex_string(&key.asset_id)))?;
        }

        let mut expected_vault_index = HashMap::new();
        for (asset_id, asset) in self.assets.iter() {
            validate_token_version(asset.token_version)?;
            if asset.platform_tag.len() > MAX_ATOMIC_PLATFORM_TAG_LEN {
                return Err(format!("atomic asset `{}` platform tag exceeds max length", faster_hex::hex_string(asset_id)));
            }
            if std::str::from_utf8(&asset.platform_tag).is_err() {
                return Err(format!("atomic asset `{}` platform tag is not valid utf-8", faster_hex::hex_string(asset_id)));
            }
            match asset.supply_mode {
                AtomicSupplyMode::Uncapped if asset.max_supply != 0 => {
                    return Err(format!("uncapped asset `{}` has non-zero max_supply", faster_hex::hex_string(asset_id)))
                }
                AtomicSupplyMode::Capped if asset.max_supply == 0 => {
                    return Err(format!("capped asset `{}` has zero max_supply", faster_hex::hex_string(asset_id)))
                }
                AtomicSupplyMode::Capped if asset.total_supply > asset.max_supply => {
                    return Err(format!("asset `{}` total_supply exceeds max_supply", faster_hex::hex_string(asset_id)))
                }
                _ => {}
            }

            let balance_total = balance_totals.get(asset_id).copied().unwrap_or(0);
            if balance_total != asset.total_supply {
                return Err(format!(
                    "asset `{}` balance total `{}` does not match total_supply `{}`",
                    faster_hex::hex_string(asset_id),
                    balance_total,
                    asset.total_supply
                ));
            }

            match asset.asset_class {
                AtomicAssetClass::Standard => {
                    if asset.liquidity.is_some() {
                        return Err(format!("standard asset `{}` has liquidity state", faster_hex::hex_string(asset_id)));
                    }
                }
                AtomicAssetClass::Liquidity => {
                    validate_liquidity_asset_normalized(*asset_id, asset, &mut expected_vault_index)?;
                }
            }
        }

        if self.liquidity_vault_outpoints != expected_vault_index {
            return Err("liquidity vault outpoint index is not normalized".to_string());
        }

        Ok(())
    }
}

fn validate_liquidity_asset_normalized(
    asset_id: [u8; 32],
    asset: &AtomicAssetState,
    expected_vault_index: &mut HashMap<TransactionOutpoint, [u8; 32]>,
) -> Result<(), String> {
    let pool = asset
        .liquidity
        .as_ref()
        .ok_or_else(|| format!("liquidity asset `{}` is missing pool state", faster_hex::hex_string(&asset_id)))?;
    if asset.mint_authority_owner_id != [0u8; 32] {
        return Err(format!("liquidity asset `{}` has non-zero mint authority", faster_hex::hex_string(&asset_id)));
    }
    if !matches!(asset.supply_mode, AtomicSupplyMode::Capped) {
        return Err(format!("liquidity asset `{}` is not capped", faster_hex::hex_string(&asset_id)));
    }
    if pool.pool_nonce == 0 {
        return Err(format!("liquidity asset `{}` has zero pool nonce", faster_hex::hex_string(&asset_id)));
    }
    validate_liquidity_curve_version(pool.curve_version)?;
    validate_liquidity_curve_mode(pool.curve_mode)?;
    validate_liquidity_curve_parameters(
        pool.curve_mode,
        pool.individual_virtual_cpay_reserves_sompi,
        pool.individual_virtual_token_multiplier_bps,
    )?;
    if pool.unlock_target_sompi == 0 && !pool.unlocked {
        return Err(format!("liquidity asset `{}` has disabled lock but is not marked unlocked", faster_hex::hex_string(&asset_id)));
    }
    if pool.unlock_target_sompi > MAX_SOMPI {
        return Err(format!("liquidity asset `{}` unlock target exceeds MAX_SOMPI", faster_hex::hex_string(&asset_id)));
    }
    if pool.unlock_target_sompi > 0 && !pool.unlocked && pool.real_cpay_reserves_sompi >= pool.unlock_target_sompi {
        return Err(format!(
            "liquidity asset `{}` reached unlock target but is not marked unlocked",
            faster_hex::hex_string(&asset_id)
        ));
    }
    if pool.real_cpay_reserves_sompi == 0 {
        return Err(format!("liquidity asset `{}` has zero real CPAY reserve", faster_hex::hex_string(&asset_id)));
    }
    if pool.real_token_reserves == 0 {
        return Err(format!("liquidity asset `{}` has zero real token reserve", faster_hex::hex_string(&asset_id)));
    }
    if pool.virtual_cpay_reserves_sompi == 0 || pool.virtual_token_reserves == 0 {
        return Err(format!("liquidity asset `{}` has zero virtual reserve", faster_hex::hex_string(&asset_id)));
    }

    let expected_vault_value = pool
        .real_cpay_reserves_sompi
        .checked_add(pool.unclaimed_fee_total_sompi)
        .ok_or_else(|| format!("liquidity asset `{}` vault value overflow", faster_hex::hex_string(&asset_id)))?;
    if pool.vault_value_sompi != expected_vault_value {
        return Err(format!("liquidity asset `{}` vault value invariant violation", faster_hex::hex_string(&asset_id)));
    }

    let expected_supply = asset
        .total_supply
        .checked_add(pool.real_token_reserves)
        .ok_or_else(|| format!("liquidity asset `{}` supply invariant overflow", faster_hex::hex_string(&asset_id)))?;
    if expected_supply != asset.max_supply {
        return Err(format!("liquidity asset `{}` supply invariant violation", faster_hex::hex_string(&asset_id)));
    }

    validate_fee_recipients_normalized(asset_id, pool)?;

    if let Some(previous_asset_id) = expected_vault_index.insert(pool.vault_outpoint, asset_id) {
        if previous_asset_id != asset_id {
            return Err(format!("multiple liquidity assets share vault outpoint `{}`", pool.vault_outpoint));
        }
    }

    Ok(())
}

fn validate_fee_recipients_normalized(asset_id: [u8; 32], pool: &AtomicLiquidityPoolState) -> Result<(), String> {
    match pool.fee_bps {
        0 if !pool.fee_recipients.is_empty() => {
            return Err(format!("liquidity asset `{}` has recipients with zero fee_bps", faster_hex::hex_string(&asset_id)))
        }
        0 => {}
        MIN_ATOMIC_LIQUIDITY_FEE_BPS..=MAX_ATOMIC_LIQUIDITY_FEE_BPS => {
            if pool.fee_recipients.is_empty() || pool.fee_recipients.len() > MAX_ATOMIC_LIQUIDITY_FEE_RECIPIENTS {
                return Err(format!("liquidity asset `{}` has invalid fee recipient count", faster_hex::hex_string(&asset_id)));
            }
        }
        _ => return Err(format!("liquidity asset `{}` has invalid fee_bps", faster_hex::hex_string(&asset_id))),
    }

    let mut unclaimed_sum = 0u64;
    let mut previous_order_key: Option<(u8, &[u8])> = None;
    for recipient in pool.fee_recipients.iter() {
        let owner_id = atomic_owner_id_from_address_components(recipient.address_version, &recipient.address_payload)
            .ok_or_else(|| format!("liquidity asset `{}` has invalid fee recipient address", faster_hex::hex_string(&asset_id)))?;
        if owner_id != recipient.owner_id {
            return Err(format!("liquidity asset `{}` fee recipient owner mismatch", faster_hex::hex_string(&asset_id)));
        }

        let order_key = (recipient.address_version, recipient.address_payload.as_slice());
        if previous_order_key.is_some_and(|previous| previous >= order_key) {
            return Err(format!(
                "liquidity asset `{}` fee recipients are duplicated or not canonically sorted",
                faster_hex::hex_string(&asset_id)
            ));
        }
        previous_order_key = Some(order_key);

        unclaimed_sum = unclaimed_sum
            .checked_add(recipient.unclaimed_sompi)
            .ok_or_else(|| format!("liquidity asset `{}` fee recipient total overflow", faster_hex::hex_string(&asset_id)))?;
    }
    if unclaimed_sum != pool.unclaimed_fee_total_sompi {
        return Err(format!("liquidity asset `{}` fee total invariant violation", faster_hex::hex_string(&asset_id)));
    }

    Ok(())
}

fn validate_token_version(version: u8) -> Result<(), String> {
    if (1..=ATOMIC_MAX_TOKEN_VERSION).contains(&version) && version == ATOMIC_CURRENT_TOKEN_VERSION {
        Ok(())
    } else {
        Err(format!("unsupported atomic token version `{version}`"))
    }
}

fn validate_liquidity_curve_version(version: u8) -> Result<(), String> {
    if (1..=ATOMIC_MAX_LIQUIDITY_CURVE_VERSION).contains(&version) && version == ATOMIC_CURRENT_LIQUIDITY_CURVE_VERSION {
        Ok(())
    } else {
        Err(format!("unsupported atomic liquidity curve version `{version}`"))
    }
}

fn validate_liquidity_curve_mode(mode: u8) -> Result<(), String> {
    match mode {
        ATOMIC_LIQUIDITY_CURVE_MODE_BASIC | ATOMIC_LIQUIDITY_CURVE_MODE_AGGRESSIVE | ATOMIC_LIQUIDITY_CURVE_MODE_INDIVIDUAL => Ok(()),
        _ => Err(format!("unsupported atomic liquidity curve mode `{mode}`")),
    }
}

fn validate_individual_liquidity_curve_params(
    virtual_cpay_reserves_sompi: u64,
    virtual_token_multiplier_bps: u16,
) -> Result<(), String> {
    if !(ATOMIC_INDIVIDUAL_MIN_VIRTUAL_CPAY_RESERVES_SOMPI..=ATOMIC_INDIVIDUAL_MAX_VIRTUAL_CPAY_RESERVES_SOMPI)
        .contains(&virtual_cpay_reserves_sompi)
    {
        return Err(format!("individual liquidity fixed CPAY `{virtual_cpay_reserves_sompi}` is outside allowed range"));
    }
    if virtual_cpay_reserves_sompi % ATOMIC_INDIVIDUAL_VIRTUAL_CPAY_STEP_SOMPI != 0 {
        return Err(format!("individual liquidity fixed CPAY `{virtual_cpay_reserves_sompi}` is not on the allowed step"));
    }
    if !(ATOMIC_INDIVIDUAL_MIN_VIRTUAL_TOKEN_MULTIPLIER_BPS..=ATOMIC_INDIVIDUAL_MAX_VIRTUAL_TOKEN_MULTIPLIER_BPS)
        .contains(&virtual_token_multiplier_bps)
    {
        return Err(format!("individual liquidity multiplier `{virtual_token_multiplier_bps}` is outside allowed range"));
    }
    if virtual_token_multiplier_bps % ATOMIC_INDIVIDUAL_VIRTUAL_TOKEN_MULTIPLIER_STEP_BPS != 0 {
        return Err(format!("individual liquidity multiplier `{virtual_token_multiplier_bps}` is not on the allowed step"));
    }
    Ok(())
}

fn validate_liquidity_curve_parameters(
    mode: u8,
    individual_virtual_cpay_reserves_sompi: u64,
    individual_virtual_token_multiplier_bps: u16,
) -> Result<(), String> {
    match mode {
        ATOMIC_LIQUIDITY_CURVE_MODE_BASIC | ATOMIC_LIQUIDITY_CURVE_MODE_AGGRESSIVE => {
            if individual_virtual_cpay_reserves_sompi == 0 && individual_virtual_token_multiplier_bps == 0 {
                Ok(())
            } else {
                Err("non-individual liquidity curve must not encode individual parameters".to_string())
            }
        }
        ATOMIC_LIQUIDITY_CURVE_MODE_INDIVIDUAL => {
            validate_individual_liquidity_curve_params(individual_virtual_cpay_reserves_sompi, individual_virtual_token_multiplier_bps)
        }
        _ => Err(format!("unsupported atomic liquidity curve mode `{mode}`")),
    }
}

fn atomic_owner_id_from_address_components(address_version: u8, address_payload: &[u8]) -> Option<[u8; 32]> {
    let auth_scheme = match address_version {
        0 if address_payload.len() == 32 => OWNER_AUTH_SCHEME_PUBKEY,
        1 if address_payload.len() == 33 => OWNER_AUTH_SCHEME_PUBKEY_ECDSA,
        8 if address_payload.len() == 32 => OWNER_AUTH_SCHEME_SCRIPT_HASH,
        _ => return None,
    };
    let pubkey_len = u16::try_from(address_payload.len()).ok()?;
    let mut hasher = Blake2bParams::new().hash_length(32).to_state();
    hasher.update(ATOMIC_OWNER_DOMAIN);
    hasher.update(&[auth_scheme]);
    hasher.update(&pubkey_len.to_le_bytes());
    hasher.update(address_payload);
    let hash = hasher.finalize();
    let mut owner_id = [0u8; 32];
    owner_id.copy_from_slice(hash.as_bytes());
    Some(owner_id)
}

fn write_len(out: &mut Vec<u8>, len: usize) {
    write_u64(out, len as u64);
}

fn write_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u128(out: &mut Vec<u8>, value: u128) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_asset(out: &mut Vec<u8>, asset: &AtomicAssetState) {
    write_u8(out, atomic_asset_class_to_u8(asset.asset_class));
    write_u8(out, asset.token_version);
    out.extend_from_slice(&asset.mint_authority_owner_id);
    write_u8(out, atomic_supply_mode_to_u8(asset.supply_mode));
    write_u128(out, asset.max_supply);
    write_u128(out, asset.total_supply);
    write_len(out, asset.platform_tag.len());
    out.extend_from_slice(&asset.platform_tag);
    match asset.liquidity.as_ref() {
        Some(pool) => {
            write_u8(out, 1);
            write_liquidity_pool(out, pool);
        }
        None => write_u8(out, 0),
    }
}

fn write_liquidity_pool(out: &mut Vec<u8>, pool: &AtomicLiquidityPoolState) {
    write_u64(out, pool.pool_nonce);
    write_u8(out, pool.curve_version);
    write_u8(out, pool.curve_mode);
    write_u64(out, pool.individual_virtual_cpay_reserves_sompi);
    write_u16(out, pool.individual_virtual_token_multiplier_bps);
    write_u64(out, pool.real_cpay_reserves_sompi);
    write_u128(out, pool.real_token_reserves);
    write_u64(out, pool.virtual_cpay_reserves_sompi);
    write_u128(out, pool.virtual_token_reserves);
    write_u64(out, pool.unclaimed_fee_total_sompi);
    write_u16(out, pool.fee_bps);
    write_len(out, pool.fee_recipients.len());
    for recipient in pool.fee_recipients.iter() {
        out.extend_from_slice(&recipient.owner_id);
        write_u8(out, recipient.address_version);
        write_len(out, recipient.address_payload.len());
        out.extend_from_slice(&recipient.address_payload);
        write_u64(out, recipient.unclaimed_sompi);
    }
    write_outpoint(out, pool.vault_outpoint);
    write_u64(out, pool.vault_value_sompi);
    write_u64(out, pool.unlock_target_sompi);
    write_u8(out, u8::from(pool.unlocked));
}

fn write_outpoint(out: &mut Vec<u8>, outpoint: TransactionOutpoint) {
    out.extend_from_slice(&outpoint.transaction_id.as_bytes());
    write_u32(out, outpoint.index);
}

fn atomic_asset_class_to_u8(value: AtomicAssetClass) -> u8 {
    match value {
        AtomicAssetClass::Standard => 0,
        AtomicAssetClass::Liquidity => 1,
    }
}

fn atomic_supply_mode_to_u8(value: AtomicSupplyMode) -> u8 {
    match value {
        AtomicSupplyMode::Uncapped => 0,
        AtomicSupplyMode::Capped => 1,
    }
}

struct AtomicStateReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> AtomicStateReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self.cursor.checked_add(len).ok_or_else(|| "atomic state cursor overflow".to_string())?;
        let slice = self.bytes.get(self.cursor..end).ok_or_else(|| "truncated atomic consensus state".to_string())?;
        self.cursor = end;
        Ok(slice)
    }

    fn read_32(&mut self) -> Result<[u8; 32], String> {
        let mut out = [0u8; 32];
        out.copy_from_slice(self.read_bytes(32)?);
        Ok(out)
    }

    fn read_u8(&mut self) -> Result<u8, String> {
        Ok(*self.read_bytes(1)?.first().expect("slice length is one"))
    }

    fn read_u16(&mut self) -> Result<u16, String> {
        let mut out = [0u8; 2];
        out.copy_from_slice(self.read_bytes(2)?);
        Ok(u16::from_le_bytes(out))
    }

    fn read_u32(&mut self) -> Result<u32, String> {
        let mut out = [0u8; 4];
        out.copy_from_slice(self.read_bytes(4)?);
        Ok(u32::from_le_bytes(out))
    }

    fn read_u64(&mut self) -> Result<u64, String> {
        let mut out = [0u8; 8];
        out.copy_from_slice(self.read_bytes(8)?);
        Ok(u64::from_le_bytes(out))
    }

    fn read_u128(&mut self) -> Result<u128, String> {
        let mut out = [0u8; 16];
        out.copy_from_slice(self.read_bytes(16)?);
        Ok(u128::from_le_bytes(out))
    }

    fn read_len(&mut self) -> Result<usize, String> {
        usize::try_from(self.read_u64()?).map_err(|_| "atomic state length does not fit usize".to_string())
    }

    fn read_asset(&mut self) -> Result<AtomicAssetState, String> {
        let asset_class = match self.read_u8()? {
            0 => AtomicAssetClass::Standard,
            1 => AtomicAssetClass::Liquidity,
            other => return Err(format!("invalid atomic asset class `{other}`")),
        };
        let token_version = self.read_u8()?;
        validate_token_version(token_version)?;
        let mint_authority_owner_id = self.read_32()?;
        let supply_mode = match self.read_u8()? {
            0 => AtomicSupplyMode::Uncapped,
            1 => AtomicSupplyMode::Capped,
            other => return Err(format!("invalid atomic supply mode `{other}`")),
        };
        let max_supply = self.read_u128()?;
        let total_supply = self.read_u128()?;
        let platform_tag_len = self.read_len()?;
        if platform_tag_len > MAX_ATOMIC_PLATFORM_TAG_LEN {
            return Err(format!("atomic platform tag length `{platform_tag_len}` exceeds max"));
        }
        let platform_tag = self.read_bytes(platform_tag_len)?.to_vec();
        if std::str::from_utf8(&platform_tag).is_err() {
            return Err("atomic platform tag must be valid utf-8".to_string());
        }
        let liquidity = match self.read_u8()? {
            0 => None,
            1 => Some(self.read_liquidity_pool()?),
            other => return Err(format!("invalid atomic liquidity presence flag `{other}`")),
        };
        Ok(AtomicAssetState {
            asset_class,
            token_version,
            mint_authority_owner_id,
            supply_mode,
            max_supply,
            total_supply,
            platform_tag,
            liquidity,
        })
    }

    fn read_liquidity_pool(&mut self) -> Result<AtomicLiquidityPoolState, String> {
        let pool_nonce = self.read_u64()?;
        let curve_version = self.read_u8()?;
        validate_liquidity_curve_version(curve_version)?;
        let curve_mode = self.read_u8()?;
        validate_liquidity_curve_mode(curve_mode)?;
        let individual_virtual_cpay_reserves_sompi = self.read_u64()?;
        let individual_virtual_token_multiplier_bps = self.read_u16()?;
        validate_liquidity_curve_parameters(
            curve_mode,
            individual_virtual_cpay_reserves_sompi,
            individual_virtual_token_multiplier_bps,
        )?;
        let real_cpay_reserves_sompi = self.read_u64()?;
        let real_token_reserves = self.read_u128()?;
        let virtual_cpay_reserves_sompi = self.read_u64()?;
        let virtual_token_reserves = self.read_u128()?;
        let unclaimed_fee_total_sompi = self.read_u64()?;
        let fee_bps = self.read_u16()?;
        let recipient_len = self.read_len()?;
        if recipient_len > MAX_ATOMIC_LIQUIDITY_FEE_RECIPIENTS {
            return Err(format!("atomic liquidity recipient count `{recipient_len}` exceeds max"));
        }
        let mut fee_recipients = Vec::with_capacity(recipient_len);
        for _ in 0..recipient_len {
            let owner_id = self.read_32()?;
            let address_version = self.read_u8()?;
            let payload_len = self.read_len()?;
            let address_payload = self.read_bytes(payload_len)?.to_vec();
            let unclaimed_sompi = self.read_u64()?;
            fee_recipients.push(AtomicLiquidityFeeRecipientState { owner_id, address_version, address_payload, unclaimed_sompi });
        }
        let vault_outpoint = self.read_outpoint()?;
        let vault_value_sompi = self.read_u64()?;
        let unlock_target_sompi = self.read_u64()?;
        let unlocked = match self.read_u8()? {
            0 => false,
            1 => true,
            other => return Err(format!("invalid atomic liquidity unlocked flag `{other}`")),
        };
        Ok(AtomicLiquidityPoolState {
            pool_nonce,
            curve_version,
            curve_mode,
            individual_virtual_cpay_reserves_sompi,
            individual_virtual_token_multiplier_bps,
            real_cpay_reserves_sompi,
            real_token_reserves,
            virtual_cpay_reserves_sompi,
            virtual_token_reserves,
            unclaimed_fee_total_sompi,
            fee_bps,
            fee_recipients,
            vault_outpoint,
            vault_value_sompi,
            unlock_target_sompi,
            unlocked,
        })
    }

    fn read_outpoint(&mut self) -> Result<TransactionOutpoint, String> {
        Ok(TransactionOutpoint::new(Hash::from_bytes(self.read_32()?), self.read_u32()?))
    }

    fn finish(&self) -> Result<(), String> {
        if self.cursor != self.bytes.len() {
            return Err("unexpected trailing bytes in atomic consensus state".to_string());
        }
        Ok(())
    }
}

pub trait AtomicStateStoreReader {
    fn get(&self, hash: Hash) -> Result<Arc<AtomicConsensusState>, StoreError>;
}

pub trait AtomicStateStore: AtomicStateStoreReader {
    fn insert(&self, hash: Hash, atomic_state: Arc<AtomicConsensusState>) -> Result<(), StoreError>;
    fn delete(&self, hash: Hash) -> Result<(), StoreError>;
}

/// Simple wrapper for implementing `MemSizeEstimator`
#[derive(Clone, Serialize, Deserialize)]
struct AtomicConsensusStateEntry(Arc<AtomicConsensusState>);

impl MemSizeEstimator for AtomicConsensusStateEntry {
    fn estimate_mem_bytes(&self) -> usize {
        let state = self.0.as_ref();
        let liquidity_heap: usize = state
            .assets
            .values()
            .map(|asset| {
                asset
                    .liquidity
                    .as_ref()
                    .map(|pool| {
                        pool.fee_recipients
                            .iter()
                            .map(|recipient| size_of::<AtomicLiquidityFeeRecipientState>() + recipient.address_payload.len())
                            .sum::<usize>()
                    })
                    .unwrap_or(0)
            })
            .sum();
        size_of::<Self>()
            + state.next_nonces.len() * (size_of::<[u8; 32]>() + size_of::<u64>())
            + state.assets.len() * (size_of::<[u8; 32]>() + size_of::<AtomicAssetState>())
            + state.balances.len() * (size_of::<AtomicBalanceKey>() + size_of::<u128>())
            + state.anchor_counts.len() * (size_of::<[u8; 32]>() + size_of::<u64>())
            + state.liquidity_vault_outpoints.len() * (size_of::<TransactionOutpoint>() + size_of::<[u8; 32]>())
            + liquidity_heap
    }
}

/// A DB + cache implementation of `DbAtomicStateStore` trait, with concurrency support.
#[derive(Clone)]
pub struct DbAtomicStateStore {
    db: Arc<DB>,
    access: CachedDbAccess<Hash, AtomicConsensusStateEntry, BlockHasher>,
}

impl DbAtomicStateStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self { db: Arc::clone(&db), access: CachedDbAccess::new(db, cache_policy, DatabaseStorePrefixes::AtomicState.into()) }
    }

    pub fn clone_with_new_cache(&self, cache_policy: CachePolicy) -> Self {
        Self::new(Arc::clone(&self.db), cache_policy)
    }

    pub fn insert_batch(&self, batch: &mut WriteBatch, hash: Hash, atomic_state: Arc<AtomicConsensusState>) -> Result<(), StoreError> {
        if self.access.has(hash)? {
            return Err(StoreError::HashAlreadyExists(hash));
        }
        self.access.write(BatchDbWriter::new(batch), hash, AtomicConsensusStateEntry(atomic_state))?;
        Ok(())
    }

    pub fn delete_batch(&self, batch: &mut WriteBatch, hash: Hash) -> Result<(), StoreError> {
        self.access.delete(BatchDbWriter::new(batch), hash)
    }
}

impl AtomicStateStoreReader for DbAtomicStateStore {
    fn get(&self, hash: Hash) -> Result<Arc<AtomicConsensusState>, StoreError> {
        Ok(self.access.read(hash)?.0)
    }
}

impl AtomicStateStore for DbAtomicStateStore {
    fn insert(&self, hash: Hash, atomic_state: Arc<AtomicConsensusState>) -> Result<(), StoreError> {
        if self.access.has(hash)? {
            return Err(StoreError::HashAlreadyExists(hash));
        }
        self.access.write(DirectDbWriter::new(&self.db), hash, AtomicConsensusStateEntry(atomic_state))?;
        Ok(())
    }

    fn delete(&self, hash: Hash) -> Result<(), StoreError> {
        self.access.delete(DirectDbWriter::new(&self.db), hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn hash(byte: u8) -> Hash {
        Hash::from_bytes([byte; 32])
    }

    fn u128_from_words(hi: u64, lo: u64) -> u128 {
        ((hi as u128) << 64) | lo as u128
    }

    fn atomic_interop_vector_state() -> AtomicConsensusState {
        let standard_asset_id = [0x10; 32];
        let liquidity_asset_id = [0x20; 32];

        let standard_total = u128_from_words(0x0100, 12_345);
        let standard_balance_a = u128_from_words(0x0080, 1_000);
        let standard_balance_b = standard_total - standard_balance_a;

        let liquidity_total = u128_from_words(0x8000, 333);
        let liquidity_remaining = u128_from_words(0x8000, 999_667);
        let liquidity_max_supply = liquidity_total + liquidity_remaining;

        let fee_recipient_payload_a = vec![0x01; 32];
        let fee_recipient_payload_b = vec![0x02; 32];
        let fee_recipient_owner_a =
            atomic_owner_id_from_address_components(0, &fee_recipient_payload_a).expect("valid recipient owner A");
        let fee_recipient_owner_b =
            atomic_owner_id_from_address_components(0, &fee_recipient_payload_b).expect("valid recipient owner B");

        let standard_asset = AtomicAssetState {
            asset_class: AtomicAssetClass::Standard,
            token_version: ATOMIC_CURRENT_TOKEN_VERSION,
            mint_authority_owner_id: owner(0xA1),
            supply_mode: AtomicSupplyMode::Capped,
            max_supply: u128_from_words(0x0200, 9_999),
            total_supply: standard_total,
            platform_tag: Vec::new(),
            liquidity: None,
        };
        let liquidity_asset = AtomicAssetState {
            asset_class: AtomicAssetClass::Liquidity,
            token_version: ATOMIC_CURRENT_TOKEN_VERSION,
            mint_authority_owner_id: [0; 32],
            supply_mode: AtomicSupplyMode::Capped,
            max_supply: liquidity_max_supply,
            total_supply: liquidity_total,
            platform_tag: Vec::new(),
            liquidity: Some(AtomicLiquidityPoolState {
                pool_nonce: 17,
                curve_version: ATOMIC_CURRENT_LIQUIDITY_CURVE_VERSION,
                curve_mode: ATOMIC_DEFAULT_LIQUIDITY_CURVE_MODE,
                individual_virtual_cpay_reserves_sompi: 0,
                individual_virtual_token_multiplier_bps: 0,
                real_cpay_reserves_sompi: 123_456_789,
                real_token_reserves: liquidity_remaining,
                virtual_cpay_reserves_sompi: 1_000_000_000_000,
                virtual_token_reserves: 1_300_000,
                unclaimed_fee_total_sompi: 30,
                fee_bps: 250,
                fee_recipients: vec![
                    AtomicLiquidityFeeRecipientState {
                        owner_id: fee_recipient_owner_a,
                        address_version: 0,
                        address_payload: fee_recipient_payload_a,
                        unclaimed_sompi: 10,
                    },
                    AtomicLiquidityFeeRecipientState {
                        owner_id: fee_recipient_owner_b,
                        address_version: 0,
                        address_payload: fee_recipient_payload_b,
                        unclaimed_sompi: 20,
                    },
                ],
                vault_outpoint: TransactionOutpoint::new(hash(0x77), 3),
                vault_value_sompi: 123_456_819,
                unlock_target_sompi: 0,
                unlocked: true,
            }),
        };

        let mut state = AtomicConsensusState::default();
        state.next_nonces.insert(owner(0x61), 3);
        state.next_nonces.insert(owner(0x60), 99);
        state.assets.insert(liquidity_asset_id, liquidity_asset);
        state.assets.insert(standard_asset_id, standard_asset);
        state.balances.insert(AtomicBalanceKey { asset_id: standard_asset_id, owner_id: owner(0xB1) }, standard_balance_b);
        state.balances.insert(AtomicBalanceKey { asset_id: liquidity_asset_id, owner_id: owner(0xC0) }, liquidity_total);
        state.balances.insert(AtomicBalanceKey { asset_id: standard_asset_id, owner_id: owner(0xB0) }, standard_balance_a);
        state.anchor_counts.insert(owner(0x51), 2);
        state.anchor_counts.insert(owner(0x50), 9);
        state.rebuild_liquidity_vault_outpoint_index();
        state
    }

    fn atomic_interop_vector_json() -> serde_json::Value {
        let state = atomic_interop_vector_state();
        state.validate_normalized().expect("interop vector state must be normalized");
        let canonical_bytes = state.to_canonical_bytes();
        let state_hash = state.canonical_hash();
        let raw_utxo_commitment = hash(0x31);
        let pre_hf_commitment = AtomicConsensusState::header_commitment(raw_utxo_commitment, state_hash, false);
        let post_hf_commitment = AtomicConsensusState::header_commitment(raw_utxo_commitment, state_hash, true);

        let decoded = AtomicConsensusState::from_canonical_bytes(&canonical_bytes).expect("canonical state should decode");
        decoded.validate_normalized().expect("decoded interop vector state must be normalized");
        assert_eq!(decoded.to_canonical_bytes(), canonical_bytes);

        serde_json::json!({
            "name": "cryptix-atomic-consensus-state-interop-v1",
            "state_canonical_hex": faster_hex::hex_string(&canonical_bytes),
            "state_hash_hex": faster_hex::hex_string(&state_hash),
            "raw_utxo_commitment_hex": raw_utxo_commitment.to_string(),
            "header_commitment_pre_hf_hex": pre_hf_commitment.to_string(),
            "header_commitment_post_hf_hex": post_hf_commitment.to_string()
        })
    }

    #[test]
    fn header_commitment_is_legacy_before_hf_and_binds_atomic_state_after_hf() {
        let utxo_commitment = hash(1);
        let atomic_hash_a = [2u8; 32];
        let atomic_hash_b = [3u8; 32];

        assert_eq!(AtomicConsensusState::header_commitment(utxo_commitment, atomic_hash_a, false), utxo_commitment);

        let commitment_a = AtomicConsensusState::header_commitment(utxo_commitment, atomic_hash_a, true);
        let commitment_b = AtomicConsensusState::header_commitment(utxo_commitment, atomic_hash_b, true);
        assert_ne!(commitment_a, utxo_commitment);
        assert_ne!(commitment_a, commitment_b);
    }

    #[test]
    fn canonical_atomic_state_bytes_are_order_independent_and_roundtrip() {
        let asset_a = [0xA0; 32];
        let asset_b = [0xB0; 32];
        let mut left = AtomicConsensusState::default();
        let mut right = AtomicConsensusState::default();

        let standard_asset = AtomicAssetState {
            asset_class: AtomicAssetClass::Standard,
            token_version: ATOMIC_CURRENT_TOKEN_VERSION,
            mint_authority_owner_id: owner(1),
            supply_mode: AtomicSupplyMode::Capped,
            max_supply: 1_000,
            total_supply: 11,
            platform_tag: Vec::new(),
            liquidity: None,
        };
        let fee_recipient_payload = vec![4; 32];
        let fee_recipient_owner =
            atomic_owner_id_from_address_components(0, &fee_recipient_payload).expect("test recipient owner should derive");
        let liquidity_asset = AtomicAssetState {
            asset_class: AtomicAssetClass::Liquidity,
            token_version: ATOMIC_CURRENT_TOKEN_VERSION,
            mint_authority_owner_id: [0; 32],
            supply_mode: AtomicSupplyMode::Capped,
            max_supply: 10_000,
            total_supply: 500,
            platform_tag: Vec::new(),
            liquidity: Some(AtomicLiquidityPoolState {
                pool_nonce: 7,
                curve_version: ATOMIC_CURRENT_LIQUIDITY_CURVE_VERSION,
                curve_mode: ATOMIC_DEFAULT_LIQUIDITY_CURVE_MODE,
                individual_virtual_cpay_reserves_sompi: 0,
                individual_virtual_token_multiplier_bps: 0,
                real_cpay_reserves_sompi: 250,
                real_token_reserves: 9_500,
                virtual_cpay_reserves_sompi: 1_000_000_000_000,
                virtual_token_reserves: 1_300_000,
                unclaimed_fee_total_sompi: 3,
                fee_bps: 100,
                fee_recipients: vec![AtomicLiquidityFeeRecipientState {
                    owner_id: fee_recipient_owner,
                    address_version: 0,
                    address_payload: fee_recipient_payload,
                    unclaimed_sompi: 3,
                }],
                vault_outpoint: TransactionOutpoint::new(hash(9), 1),
                vault_value_sompi: 253,
                unlock_target_sompi: 0,
                unlocked: true,
            }),
        };

        left.next_nonces.insert(owner(5), 2);
        left.next_nonces.insert(owner(4), 9);
        left.assets.insert(asset_b, liquidity_asset.clone());
        left.assets.insert(asset_a, standard_asset.clone());
        left.balances.insert(AtomicBalanceKey { asset_id: asset_b, owner_id: owner(8) }, 500);
        left.balances.insert(AtomicBalanceKey { asset_id: asset_a, owner_id: owner(7) }, 11);
        left.anchor_counts.insert(owner(6), 1);
        left.rebuild_liquidity_vault_outpoint_index();

        right.anchor_counts.insert(owner(6), 1);
        right.balances.insert(AtomicBalanceKey { asset_id: asset_a, owner_id: owner(7) }, 11);
        right.balances.insert(AtomicBalanceKey { asset_id: asset_b, owner_id: owner(8) }, 500);
        right.assets.insert(asset_a, standard_asset);
        right.assets.insert(asset_b, liquidity_asset);
        right.next_nonces.insert(owner(4), 9);
        right.next_nonces.insert(owner(5), 2);
        right.rebuild_liquidity_vault_outpoint_index();

        left.validate_normalized().expect("left state should be normalized");
        right.validate_normalized().expect("right state should be normalized");
        assert_eq!(left.to_canonical_bytes(), right.to_canonical_bytes());
        assert_eq!(left.canonical_hash(), right.canonical_hash());

        let decoded = AtomicConsensusState::from_canonical_bytes(&left.to_canonical_bytes()).expect("canonical state should decode");
        decoded.validate_normalized().expect("decoded state should be normalized");
        assert_eq!(decoded.to_canonical_bytes(), left.to_canonical_bytes());
        assert_eq!(decoded.liquidity_vault_outpoints.get(&TransactionOutpoint::new(hash(9), 1)), Some(&asset_b));
    }

    #[test]
    fn atomic_consensus_state_interop_vector_matches_fixture() {
        let fixture_path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("docs").join("atomic_consensus_state_interop_v1.json");
        let actual = atomic_interop_vector_json();
        if std::env::var_os("CRYPTIX_WRITE_ATOMIC_INTEROP_VECTOR").is_some() {
            let json = serde_json::to_string_pretty(&actual).expect("serialize interop vector");
            std::fs::write(&fixture_path, format!("{json}\n")).expect("write interop vector fixture");
            return;
        }

        let expected_bytes = std::fs::read(&fixture_path).expect("read interop vector fixture");
        let expected: serde_json::Value = serde_json::from_slice(&expected_bytes).expect("parse interop vector fixture");
        assert_eq!(actual, expected);
    }
}
