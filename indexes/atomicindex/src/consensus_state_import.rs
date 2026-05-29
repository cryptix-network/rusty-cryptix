use crate::{
    error::{AtomicTokenError, AtomicTokenResult},
    liquidity_math::{validate_liquidity_curve_mode, validate_liquidity_curve_parameters},
    payload::{
        SupplyMode, CURRENT_LIQUIDITY_CURVE_VERSION, CURRENT_TOKEN_VERSION, MAX_DECIMALS, MAX_LIQUIDITY_FEE_BPS,
        MAX_LIQUIDITY_RECIPIENTS, MAX_METADATA_LEN, MAX_NAME_LEN, MAX_PLATFORM_TAG_LEN, MAX_SYMBOL_LEN, MIN_LIQUIDITY_FEE_BPS,
    },
    state::{
        AtomicTokenState, BalanceKey, LiquidityFeeRecipientState, LiquidityHolderAddressState, LiquidityPoolState, NonceKey,
        TokenAsset, TokenAssetClass,
    },
};
use cryptix_consensus_core::{tx::TransactionOutpoint, Hash as BlockHash};
use std::collections::HashMap;

const ATOMIC_CONSENSUS_STATE_MAGIC: &[u8] = b"CATCSG02";
const ATOMIC_CONSENSUS_STATE_ROOT_ONLY_TAG: &[u8] = b"ROOT";

pub(crate) fn token_state_from_consensus_canonical_bytes(
    bytes: &[u8],
    protocol_version: u16,
    network_id: String,
) -> AtomicTokenResult<AtomicTokenState> {
    if is_root_only_consensus_state(bytes)? {
        return Err(AtomicTokenError::Processing(
            "consensus pruning-point Atomic state only carried a root; full state bytes are required for token index bootstrap"
                .to_string(),
        ));
    }

    let mut reader = AtomicStateReader::new(bytes);
    reader.read_exact_magic(ATOMIC_CONSENSUS_STATE_MAGIC)?;
    let mut state = AtomicTokenState::new(protocol_version, network_id);

    let nonce_count = reader.read_len_usize("nonce count")?;
    for _ in 0..nonce_count {
        let owner_id = reader.read_hash32()?;
        let scope_kind = reader.read_u8()?;
        let scope_id = reader.read_hash32()?;
        let key = NonceKey { owner_id, scope_kind, scope_id };
        let value = reader.read_u64()?;
        if state.nonces.insert(key, value).is_some() {
            return Err(import_error("duplicate consensus Atomic nonce key"));
        }
    }

    let asset_count = reader.read_len_usize("asset count")?;
    for _ in 0..asset_count {
        let asset_id = reader.read_hash32()?;
        let asset = reader.read_token_asset(asset_id)?;
        if state.assets.insert(asset_id, asset).is_some() {
            return Err(import_error("duplicate consensus Atomic asset id"));
        }
    }

    let balance_count = reader.read_len_usize("balance count")?;
    for _ in 0..balance_count {
        let asset_id = reader.read_hash32()?;
        let owner_id = reader.read_hash32()?;
        let key = BalanceKey { asset_id, owner_id };
        let value = reader.read_u128()?;
        if state.balances.insert(key, value).is_some() {
            return Err(import_error("duplicate consensus Atomic balance key"));
        }
    }

    let anchor_count = reader.read_len_usize("anchor count")?;
    for _ in 0..anchor_count {
        let owner_id = reader.read_hash32()?;
        let value = reader.read_u64()?;
        if state.anchor_counts.insert(owner_id, value).is_some() {
            return Err(import_error("duplicate consensus Atomic anchor owner id"));
        }
    }

    reader.finish()?;
    state.rebuild_runtime_caches();
    Ok(state)
}

fn is_root_only_consensus_state(bytes: &[u8]) -> AtomicTokenResult<bool> {
    if bytes.len() != ATOMIC_CONSENSUS_STATE_MAGIC.len() + ATOMIC_CONSENSUS_STATE_ROOT_ONLY_TAG.len() + 32 {
        return Ok(false);
    }
    if !bytes.starts_with(ATOMIC_CONSENSUS_STATE_MAGIC) {
        return Err(import_error("invalid consensus Atomic state magic"));
    }
    let tag_start = ATOMIC_CONSENSUS_STATE_MAGIC.len();
    let tag_end = tag_start + ATOMIC_CONSENSUS_STATE_ROOT_ONLY_TAG.len();
    Ok(&bytes[tag_start..tag_end] == ATOMIC_CONSENSUS_STATE_ROOT_ONLY_TAG)
}

fn import_error(message: impl Into<String>) -> AtomicTokenError {
    AtomicTokenError::Processing(format!("invalid consensus pruning-point Atomic state bytes: {}", message.into()))
}

struct AtomicStateReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> AtomicStateReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn read_bytes(&mut self, len: usize) -> AtomicTokenResult<&'a [u8]> {
        let end = self.cursor.checked_add(len).ok_or_else(|| import_error("truncated data"))?;
        if end > self.bytes.len() {
            return Err(import_error("truncated data"));
        }
        let out = &self.bytes[self.cursor..end];
        self.cursor = end;
        Ok(out)
    }

    fn read_exact_magic(&mut self, magic: &[u8]) -> AtomicTokenResult<()> {
        let actual = self.read_bytes(magic.len())?;
        if actual == magic {
            Ok(())
        } else {
            Err(import_error("invalid magic"))
        }
    }

    fn read_hash32(&mut self) -> AtomicTokenResult<[u8; 32]> {
        let mut out = [0u8; 32];
        out.copy_from_slice(self.read_bytes(32)?);
        Ok(out)
    }

    fn read_u8(&mut self) -> AtomicTokenResult<u8> {
        Ok(self.read_bytes(1)?[0])
    }

    fn read_u16(&mut self) -> AtomicTokenResult<u16> {
        let mut bytes = [0u8; 2];
        bytes.copy_from_slice(self.read_bytes(2)?);
        Ok(u16::from_le_bytes(bytes))
    }

    fn read_u32(&mut self) -> AtomicTokenResult<u32> {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(self.read_bytes(4)?);
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_u64(&mut self) -> AtomicTokenResult<u64> {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(self.read_bytes(8)?);
        Ok(u64::from_le_bytes(bytes))
    }

    fn read_u128(&mut self) -> AtomicTokenResult<u128> {
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(self.read_bytes(16)?);
        Ok(u128::from_le_bytes(bytes))
    }

    fn read_len_usize(&mut self, context: &str) -> AtomicTokenResult<usize> {
        let len = self.read_u64()?;
        usize::try_from(len).map_err(|_| import_error(format!("{context} exceeds platform limit")))
    }

    fn read_vec(&mut self, max_len: usize, context: &str) -> AtomicTokenResult<Vec<u8>> {
        let len = self.read_len_usize(context)?;
        if len > max_len {
            return Err(import_error(format!("{context} length `{len}` exceeds max `{max_len}`")));
        }
        Ok(self.read_bytes(len)?.to_vec())
    }

    fn read_optional_hash(&mut self) -> AtomicTokenResult<Option<BlockHash>> {
        match self.read_u8()? {
            0 => Ok(None),
            1 => Ok(Some(BlockHash::from_bytes(self.read_hash32()?))),
            raw => Err(import_error(format!("invalid optional hash flag `{raw}`"))),
        }
    }

    fn read_optional_u64(&mut self) -> AtomicTokenResult<Option<u64>> {
        match self.read_u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.read_u64()?)),
            raw => Err(import_error(format!("invalid optional u64 flag `{raw}`"))),
        }
    }

    fn read_token_asset(&mut self, asset_id: [u8; 32]) -> AtomicTokenResult<TokenAsset> {
        let creator_owner_id = self.read_hash32()?;
        let asset_class = match self.read_u8()? {
            0 => TokenAssetClass::Standard,
            1 => TokenAssetClass::Liquidity,
            raw => return Err(import_error(format!("invalid asset class `{raw}`"))),
        };
        let token_version = self.read_u8()?;
        if token_version != CURRENT_TOKEN_VERSION {
            return Err(import_error(format!("unsupported token version `{token_version}`")));
        }
        let mint_authority_owner_id = self.read_hash32()?;
        let decimals = self.read_u8()?;
        if decimals > MAX_DECIMALS {
            return Err(import_error(format!("decimals `{decimals}` exceed max `{MAX_DECIMALS}`")));
        }
        let supply_mode = match self.read_u8()? {
            0 => SupplyMode::Uncapped,
            1 => SupplyMode::Capped,
            raw => return Err(import_error(format!("invalid supply mode `{raw}`"))),
        };
        let max_supply = self.read_u128()?;
        let total_supply = self.read_u128()?;
        let name = self.read_vec(MAX_NAME_LEN, "name")?;
        let symbol = self.read_vec(MAX_SYMBOL_LEN, "symbol")?;
        let metadata = self.read_vec(MAX_METADATA_LEN, "metadata")?;
        if std::str::from_utf8(&name).is_err() || std::str::from_utf8(&symbol).is_err() {
            return Err(import_error("name/symbol must be valid UTF-8"));
        }
        let platform_tag = self.read_vec(MAX_PLATFORM_TAG_LEN, "platform tag")?;
        if std::str::from_utf8(&platform_tag).is_err() {
            return Err(import_error("platform tag must be valid UTF-8"));
        }
        let created_block_hash = self.read_optional_hash()?;
        let created_daa_score = self.read_optional_u64()?;
        let created_at = self.read_optional_u64()?;
        let liquidity = match self.read_u8()? {
            0 => None,
            1 => Some(self.read_liquidity_pool()?),
            raw => return Err(import_error(format!("invalid liquidity presence flag `{raw}`"))),
        };

        Ok(TokenAsset {
            asset_id,
            creator_owner_id,
            asset_class,
            token_version,
            mint_authority_owner_id,
            decimals,
            supply_mode,
            max_supply,
            total_supply,
            name,
            symbol,
            metadata,
            platform_tag,
            created_block_hash,
            created_daa_score,
            created_at,
            liquidity,
        })
    }

    fn read_liquidity_pool(&mut self) -> AtomicTokenResult<LiquidityPoolState> {
        let pool_nonce = self.read_u64()?;
        let curve_version = self.read_u8()?;
        if curve_version != CURRENT_LIQUIDITY_CURVE_VERSION {
            return Err(import_error(format!("unsupported liquidity curve version `{curve_version}`")));
        }
        let curve_mode = self.read_u8()?;
        validate_liquidity_curve_mode(curve_mode)
            .map_err(|_| import_error(format!("unsupported liquidity curve mode `{curve_mode}`")))?;
        let individual_virtual_cpay_reserves_sompi = self.read_u64()?;
        let individual_virtual_token_multiplier_bps = self.read_u16()?;
        validate_liquidity_curve_parameters(
            curve_mode,
            individual_virtual_cpay_reserves_sompi,
            individual_virtual_token_multiplier_bps,
        )
        .map_err(|_| import_error("invalid liquidity curve parameters"))?;
        let real_cpay_reserves_sompi = self.read_u64()?;
        let real_token_reserves = self.read_u128()?;
        let virtual_cpay_reserves_sompi = self.read_u64()?;
        let virtual_token_reserves = self.read_u128()?;
        let unclaimed_fee_total_sompi = self.read_u64()?;
        let fee_bps = self.read_u16()?;
        let recipient_count = self.read_len_usize("fee recipient count")?;
        if recipient_count > MAX_LIQUIDITY_RECIPIENTS {
            return Err(import_error("too many liquidity fee recipients"));
        }
        if fee_bps == 0 && recipient_count != 0 {
            return Err(import_error("zero liquidity fee with recipients"));
        }
        if fee_bps != 0 && !(MIN_LIQUIDITY_FEE_BPS..=MAX_LIQUIDITY_FEE_BPS).contains(&fee_bps) {
            return Err(import_error(format!("invalid liquidity fee bps `{fee_bps}`")));
        }
        let mut fee_recipients = Vec::with_capacity(recipient_count);
        for _ in 0..recipient_count {
            let owner_id = self.read_hash32()?;
            let address_version = self.read_u8()?;
            let address_payload = self.read_vec(64, "fee recipient address payload")?;
            let unclaimed_sompi = self.read_u64()?;
            fee_recipients.push(LiquidityFeeRecipientState { owner_id, address_version, address_payload, unclaimed_sompi });
        }
        let vault_txid = BlockHash::from_bytes(self.read_hash32()?);
        let vault_index = self.read_u32()?;
        let vault_outpoint = TransactionOutpoint::new(vault_txid, vault_index);
        let vault_value_sompi = self.read_u64()?;
        let unlock_target_sompi = self.read_u64()?;
        let unlocked = match self.read_u8()? {
            0 => false,
            1 => true,
            raw => return Err(import_error(format!("invalid liquidity unlocked flag `{raw}`"))),
        };

        Ok(LiquidityPoolState {
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
            holder_addresses: HashMap::<[u8; 32], LiquidityHolderAddressState>::new(),
        })
    }

    fn finish(&self) -> AtomicTokenResult<()> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(import_error("trailing bytes"))
        }
    }
}
