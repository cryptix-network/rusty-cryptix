use serde::{Deserialize, Serialize};

use cryptix_consensus_core::constants::MAX_SOMPI;

use crate::liquidity_math::{
    LIQUIDITY_TOKEN_DECIMALS, MAX_LIQUIDITY_SUPPLY_RAW, MIN_LIQUIDITY_SEED_RESERVE_SOMPI, MIN_LIQUIDITY_SUPPLY_RAW,
};

pub const CRYPTIX_ATOMIC_TOKEN_MAGIC: [u8; 3] = *b"CAT";
pub const CRYPTIX_ATOMIC_TOKEN_VERSION: u8 = 1;

pub const MAX_NAME_LEN: usize = 32;
pub const MAX_SYMBOL_LEN: usize = 10;
pub const MAX_METADATA_LEN: usize = 256;
pub const MAX_PLATFORM_TAG_LEN: usize = 50;
pub const MAX_DECIMALS: u8 = 18;
pub const MAX_LIQUIDITY_RECIPIENTS: usize = 2;
pub const MIN_LIQUIDITY_FEE_BPS: u16 = 10;
pub const MAX_LIQUIDITY_FEE_BPS: u16 = 1000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TokenOpCode {
    CreateAsset = 0,
    Transfer = 1,
    Mint = 2,
    Burn = 3,
    CreateAssetWithMint = 4,
    CreateLiquidityAsset = 5,
    BuyLiquidityExactIn = 6,
    SellLiquidityExactIn = 7,
    ClaimLiquidityFees = 8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum SupplyMode {
    Uncapped = 0,
    Capped = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ApplyStatus {
    Applied = 0,
    Noop = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum EventType {
    Applied = 0,
    Noop = 1,
    Reorged = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum NoopReason {
    None = 0,
    BadMagic = 1,
    BadVersion = 2,
    BadOp = 3,
    BadFlags = 4,
    BadLength = 5,
    BadUtf8 = 6,
    BadAuthInput = 7,
    BadNonce = 8,
    AssetNotFound = 9,
    AssetAlreadyExists = 10,
    UnauthorizedMint = 11,
    InvalidAmount = 12,
    InsufficientBalance = 13,
    BalanceOverflow = 14,
    SupplyOverflow = 15,
    SupplyUnderflow = 16,
    SupplyCapExceeded = 17,
    BadSupplyMode = 18,
    BadDecimals = 19,
    BadMaxSupply = 20,
    AlreadyProcessed = 21,
    InternalMalformedAcceptance = 22,
    BadLiquidityFeeBps = 23,
    BadLiquidityRecipientCount = 24,
    RecipientEncodingInvalid = 25,
    RecipientDuplicate = 26,
    RecipientNotCanonical = 27,
    BadLaunchBuyFields = 28,
    MinOutViolation = 29,
    ZeroOutput = 30,
    LegacyOpForLiquidityAsset = 31,
    NonceStale = 32,
    VaultInputCount = 33,
    VaultOutputCount = 34,
    VaultOutpointMismatch = 35,
    PayoutScriptClassInvalid = 36,
    HistoricalStateUnavailable = 37,
    BadPlatformTag = 38,
    BadLiquidityUnlockTarget = 39,
    LiquiditySellLocked = 40,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenOpHeader {
    pub op: TokenOpCode,
    pub auth_input_index: u16,
    pub nonce: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateAssetOp {
    pub decimals: u8,
    pub supply_mode: SupplyMode,
    pub max_supply: u128,
    pub mint_authority_owner_id: [u8; 32],
    pub name: Vec<u8>,
    pub symbol: Vec<u8>,
    pub metadata: Vec<u8>,
    #[serde(default)]
    pub platform_tag: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateAssetWithMintOp {
    pub decimals: u8,
    pub supply_mode: SupplyMode,
    pub max_supply: u128,
    pub mint_authority_owner_id: [u8; 32],
    pub name: Vec<u8>,
    pub symbol: Vec<u8>,
    pub metadata: Vec<u8>,
    pub initial_mint_amount: u128,
    pub initial_mint_to_owner_id: [u8; 32],
    #[serde(default)]
    pub platform_tag: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferOp {
    pub asset_id: [u8; 32],
    pub to_owner_id: [u8; 32],
    pub amount: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintOp {
    pub asset_id: [u8; 32],
    pub to_owner_id: [u8; 32],
    pub amount: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurnOp {
    pub asset_id: [u8; 32],
    pub amount: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityRecipientAddress {
    pub address_version: u8,
    pub address_payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateLiquidityAssetOp {
    pub decimals: u8,
    pub max_supply: u128,
    pub name: Vec<u8>,
    pub symbol: Vec<u8>,
    pub metadata: Vec<u8>,
    pub seed_reserve_sompi: u64,
    pub fee_bps: u16,
    pub recipients: Vec<LiquidityRecipientAddress>,
    pub launch_buy_sompi: u64,
    pub launch_buy_min_token_out: u128,
    #[serde(default)]
    pub platform_tag: Vec<u8>,
    #[serde(default)]
    pub liquidity_unlock_target_sompi: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuyLiquidityExactInOp {
    pub asset_id: [u8; 32],
    pub expected_pool_nonce: u64,
    pub cpay_in_sompi: u64,
    pub min_token_out: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SellLiquidityExactInOp {
    pub asset_id: [u8; 32],
    pub expected_pool_nonce: u64,
    pub token_in: u128,
    pub min_cpay_out_sompi: u64,
    pub cpay_receive_output_index: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimLiquidityFeesOp {
    pub asset_id: [u8; 32],
    pub expected_pool_nonce: u64,
    pub recipient_index: u8,
    pub claim_amount_sompi: u64,
    pub claim_receive_output_index: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenOp {
    CreateAsset(CreateAssetOp),
    Transfer(TransferOp),
    Mint(MintOp),
    Burn(BurnOp),
    CreateAssetWithMint(CreateAssetWithMintOp),
    CreateLiquidityAsset(CreateLiquidityAssetOp),
    BuyLiquidityExactIn(BuyLiquidityExactInOp),
    SellLiquidityExactIn(SellLiquidityExactInOp),
    ClaimLiquidityFees(ClaimLiquidityFeesOp),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedTokenPayload {
    pub header: TokenOpHeader,
    pub op: TokenOp,
}

/// Returns:
/// - `None` if payload does not belong to Cryptix Atomic Token (magic mismatch)
/// - `Some(Err(_))` if payload targets CAT but is invalid
/// - `Some(Ok(_))` when payload is valid and parseable
pub fn parse_atomic_token_payload(payload: &[u8]) -> Option<Result<ParsedTokenPayload, NoopReason>> {
    if payload.len() < CRYPTIX_ATOMIC_TOKEN_MAGIC.len() {
        return None;
    }

    if payload[0..3] != CRYPTIX_ATOMIC_TOKEN_MAGIC {
        return None;
    }

    Some(parse_atomic_token_payload_strict(payload))
}

fn parse_atomic_token_payload_strict(payload: &[u8]) -> Result<ParsedTokenPayload, NoopReason> {
    let mut cursor = 0usize;

    let magic = take_bytes(payload, &mut cursor, 3).ok_or(NoopReason::BadLength)?;
    if magic != CRYPTIX_ATOMIC_TOKEN_MAGIC {
        return Err(NoopReason::BadMagic);
    }

    let version = take_u8(payload, &mut cursor).ok_or(NoopReason::BadLength)?;
    if version != CRYPTIX_ATOMIC_TOKEN_VERSION {
        return Err(NoopReason::BadVersion);
    }

    let op_raw = take_u8(payload, &mut cursor).ok_or(NoopReason::BadLength)?;
    let op = match op_raw {
        0 => TokenOpCode::CreateAsset,
        1 => TokenOpCode::Transfer,
        2 => TokenOpCode::Mint,
        3 => TokenOpCode::Burn,
        4 => TokenOpCode::CreateAssetWithMint,
        5 => TokenOpCode::CreateLiquidityAsset,
        6 => TokenOpCode::BuyLiquidityExactIn,
        7 => TokenOpCode::SellLiquidityExactIn,
        8 => TokenOpCode::ClaimLiquidityFees,
        _ => return Err(NoopReason::BadOp),
    };

    let flags = take_u8(payload, &mut cursor).ok_or(NoopReason::BadLength)?;
    if flags != 0 {
        return Err(NoopReason::BadFlags);
    }

    let auth_input_index = take_u16_le(payload, &mut cursor).ok_or(NoopReason::BadLength)?;
    let nonce = take_u64_le(payload, &mut cursor).ok_or(NoopReason::BadLength)?;
    if nonce == 0 {
        return Err(NoopReason::BadNonce);
    }

    let header = TokenOpHeader { op, auth_input_index, nonce };
    let op = match op {
        TokenOpCode::CreateAsset => TokenOp::CreateAsset(parse_create_asset_op(payload, &mut cursor)?),
        TokenOpCode::Transfer => TokenOp::Transfer(parse_transfer_op(payload, &mut cursor)?),
        TokenOpCode::Mint => TokenOp::Mint(parse_mint_op(payload, &mut cursor)?),
        TokenOpCode::Burn => TokenOp::Burn(parse_burn_op(payload, &mut cursor)?),
        TokenOpCode::CreateAssetWithMint => TokenOp::CreateAssetWithMint(parse_create_asset_with_mint_op(payload, &mut cursor)?),
        TokenOpCode::CreateLiquidityAsset => TokenOp::CreateLiquidityAsset(parse_create_liquidity_asset_op(payload, &mut cursor)?),
        TokenOpCode::BuyLiquidityExactIn => TokenOp::BuyLiquidityExactIn(parse_buy_liquidity_exact_in_op(payload, &mut cursor)?),
        TokenOpCode::SellLiquidityExactIn => TokenOp::SellLiquidityExactIn(parse_sell_liquidity_exact_in_op(payload, &mut cursor)?),
        TokenOpCode::ClaimLiquidityFees => TokenOp::ClaimLiquidityFees(parse_claim_liquidity_fees_op(payload, &mut cursor)?),
    };

    if cursor != payload.len() {
        return Err(NoopReason::BadLength);
    }

    Ok(ParsedTokenPayload { header, op })
}

fn parse_create_asset_op(payload: &[u8], cursor: &mut usize) -> Result<CreateAssetOp, NoopReason> {
    let (decimals, supply_mode, max_supply, mint_authority_owner_id, name, symbol, metadata) =
        parse_create_asset_common(payload, cursor)?;
    let platform_tag = parse_optional_platform_tag_tail(payload, cursor)?;
    Ok(CreateAssetOp { decimals, supply_mode, max_supply, mint_authority_owner_id, name, symbol, metadata, platform_tag })
}

fn parse_transfer_op(payload: &[u8], cursor: &mut usize) -> Result<TransferOp, NoopReason> {
    let asset_id = take_32(payload, cursor).ok_or(NoopReason::BadLength)?;
    let to_owner_id = take_32(payload, cursor).ok_or(NoopReason::BadLength)?;
    let amount = take_u128_le(payload, cursor).ok_or(NoopReason::BadLength)?;

    if amount == 0 {
        return Err(NoopReason::InvalidAmount);
    }

    Ok(TransferOp { asset_id, to_owner_id, amount })
}

fn parse_mint_op(payload: &[u8], cursor: &mut usize) -> Result<MintOp, NoopReason> {
    let asset_id = take_32(payload, cursor).ok_or(NoopReason::BadLength)?;
    let to_owner_id = take_32(payload, cursor).ok_or(NoopReason::BadLength)?;
    let amount = take_u128_le(payload, cursor).ok_or(NoopReason::BadLength)?;

    if amount == 0 {
        return Err(NoopReason::InvalidAmount);
    }

    Ok(MintOp { asset_id, to_owner_id, amount })
}

fn parse_burn_op(payload: &[u8], cursor: &mut usize) -> Result<BurnOp, NoopReason> {
    let asset_id = take_32(payload, cursor).ok_or(NoopReason::BadLength)?;
    let amount = take_u128_le(payload, cursor).ok_or(NoopReason::BadLength)?;

    if amount == 0 {
        return Err(NoopReason::InvalidAmount);
    }

    Ok(BurnOp { asset_id, amount })
}

fn parse_create_asset_with_mint_op(payload: &[u8], cursor: &mut usize) -> Result<CreateAssetWithMintOp, NoopReason> {
    let (decimals, supply_mode, max_supply, mint_authority_owner_id, name, symbol, metadata) =
        parse_create_asset_common(payload, cursor)?;
    let initial_mint_amount = take_u128_le(payload, cursor).ok_or(NoopReason::BadLength)?;
    let initial_mint_to_owner_id = take_32(payload, cursor).ok_or(NoopReason::BadLength)?;

    if initial_mint_amount == 0 && initial_mint_to_owner_id != [0u8; 32] {
        return Err(NoopReason::InvalidAmount);
    }
    if initial_mint_amount > 0 && initial_mint_to_owner_id == [0u8; 32] {
        return Err(NoopReason::InvalidAmount);
    }
    let platform_tag = parse_optional_platform_tag_tail(payload, cursor)?;

    Ok(CreateAssetWithMintOp {
        decimals,
        supply_mode,
        max_supply,
        mint_authority_owner_id,
        name,
        symbol,
        metadata,
        initial_mint_amount,
        initial_mint_to_owner_id,
        platform_tag,
    })
}

fn parse_create_liquidity_asset_op(payload: &[u8], cursor: &mut usize) -> Result<CreateLiquidityAssetOp, NoopReason> {
    let decimals = take_u8(payload, cursor).ok_or(NoopReason::BadLength)?;
    if decimals != LIQUIDITY_TOKEN_DECIMALS {
        return Err(NoopReason::BadDecimals);
    }

    let max_supply = take_u128_le(payload, cursor).ok_or(NoopReason::BadLength)?;
    if !(MIN_LIQUIDITY_SUPPLY_RAW..=MAX_LIQUIDITY_SUPPLY_RAW).contains(&max_supply) {
        return Err(NoopReason::BadMaxSupply);
    }

    let name_len = take_u8(payload, cursor).ok_or(NoopReason::BadLength)? as usize;
    let symbol_len = take_u8(payload, cursor).ok_or(NoopReason::BadLength)? as usize;
    let metadata_len = take_u16_le(payload, cursor).ok_or(NoopReason::BadLength)? as usize;
    if name_len > MAX_NAME_LEN || symbol_len > MAX_SYMBOL_LEN || metadata_len > MAX_METADATA_LEN {
        return Err(NoopReason::BadLength);
    }

    let name = take_vec(payload, cursor, name_len).ok_or(NoopReason::BadLength)?;
    let symbol = take_vec(payload, cursor, symbol_len).ok_or(NoopReason::BadLength)?;
    let metadata = take_vec(payload, cursor, metadata_len).ok_or(NoopReason::BadLength)?;
    if std::str::from_utf8(&name).is_err() || std::str::from_utf8(&symbol).is_err() {
        return Err(NoopReason::BadUtf8);
    }

    let seed_reserve_sompi = take_u64_le(payload, cursor).ok_or(NoopReason::BadLength)?;
    if seed_reserve_sompi != MIN_LIQUIDITY_SEED_RESERVE_SOMPI {
        return Err(NoopReason::InvalidAmount);
    }

    let fee_bps = take_u16_le(payload, cursor).ok_or(NoopReason::BadLength)?;
    if !(fee_bps == 0 || (MIN_LIQUIDITY_FEE_BPS..=MAX_LIQUIDITY_FEE_BPS).contains(&fee_bps)) {
        return Err(NoopReason::BadLiquidityFeeBps);
    }

    let recipient_count = take_u8(payload, cursor).ok_or(NoopReason::BadLength)? as usize;
    if recipient_count > MAX_LIQUIDITY_RECIPIENTS {
        return Err(NoopReason::BadLiquidityRecipientCount);
    }
    if fee_bps == 0 && recipient_count != 0 {
        return Err(NoopReason::BadLiquidityRecipientCount);
    }
    if fee_bps > 0 && !(1..=MAX_LIQUIDITY_RECIPIENTS).contains(&recipient_count) {
        return Err(NoopReason::BadLiquidityRecipientCount);
    }

    let mut recipients = Vec::with_capacity(recipient_count);
    for _ in 0..recipient_count {
        recipients.push(parse_recipient_address(payload, cursor)?);
    }
    if recipients.len() == 2 {
        if recipients[0] == recipients[1] {
            return Err(NoopReason::RecipientDuplicate);
        }
        if recipient_order_key(&recipients[0]) > recipient_order_key(&recipients[1]) {
            return Err(NoopReason::RecipientNotCanonical);
        }
    }

    let launch_buy_sompi = take_u64_le(payload, cursor).ok_or(NoopReason::BadLength)?;
    let launch_buy_min_token_out = take_u128_le(payload, cursor).ok_or(NoopReason::BadLength)?;
    if launch_buy_sompi == 0 && launch_buy_min_token_out != 0 {
        return Err(NoopReason::BadLaunchBuyFields);
    }
    if launch_buy_sompi > 0 && launch_buy_min_token_out == 0 {
        return Err(NoopReason::BadLaunchBuyFields);
    }

    let (platform_tag, liquidity_unlock_target_sompi) = parse_optional_liquidity_create_tail(payload, cursor)?;

    Ok(CreateLiquidityAssetOp {
        decimals,
        max_supply,
        name,
        symbol,
        metadata,
        seed_reserve_sompi,
        fee_bps,
        recipients,
        launch_buy_sompi,
        launch_buy_min_token_out,
        platform_tag,
        liquidity_unlock_target_sompi,
    })
}

fn parse_buy_liquidity_exact_in_op(payload: &[u8], cursor: &mut usize) -> Result<BuyLiquidityExactInOp, NoopReason> {
    let asset_id = take_32(payload, cursor).ok_or(NoopReason::BadLength)?;
    let expected_pool_nonce = take_u64_le(payload, cursor).ok_or(NoopReason::BadLength)?;
    let cpay_in_sompi = take_u64_le(payload, cursor).ok_or(NoopReason::BadLength)?;
    let min_token_out = take_u128_le(payload, cursor).ok_or(NoopReason::BadLength)?;

    if expected_pool_nonce == 0 {
        return Err(NoopReason::BadNonce);
    }
    if cpay_in_sompi == 0 {
        return Err(NoopReason::InvalidAmount);
    }
    if min_token_out == 0 {
        return Err(NoopReason::MinOutViolation);
    }

    Ok(BuyLiquidityExactInOp { asset_id, expected_pool_nonce, cpay_in_sompi, min_token_out })
}

fn parse_sell_liquidity_exact_in_op(payload: &[u8], cursor: &mut usize) -> Result<SellLiquidityExactInOp, NoopReason> {
    let asset_id = take_32(payload, cursor).ok_or(NoopReason::BadLength)?;
    let expected_pool_nonce = take_u64_le(payload, cursor).ok_or(NoopReason::BadLength)?;
    let token_in = take_u128_le(payload, cursor).ok_or(NoopReason::BadLength)?;
    let min_cpay_out_sompi = take_u64_le(payload, cursor).ok_or(NoopReason::BadLength)?;
    let cpay_receive_output_index = take_u16_le(payload, cursor).ok_or(NoopReason::BadLength)?;

    if expected_pool_nonce == 0 {
        return Err(NoopReason::BadNonce);
    }
    if token_in == 0 {
        return Err(NoopReason::InvalidAmount);
    }
    if min_cpay_out_sompi == 0 {
        return Err(NoopReason::MinOutViolation);
    }

    Ok(SellLiquidityExactInOp { asset_id, expected_pool_nonce, token_in, min_cpay_out_sompi, cpay_receive_output_index })
}

fn parse_claim_liquidity_fees_op(payload: &[u8], cursor: &mut usize) -> Result<ClaimLiquidityFeesOp, NoopReason> {
    let asset_id = take_32(payload, cursor).ok_or(NoopReason::BadLength)?;
    let expected_pool_nonce = take_u64_le(payload, cursor).ok_or(NoopReason::BadLength)?;
    let recipient_index = take_u8(payload, cursor).ok_or(NoopReason::BadLength)?;
    let claim_amount_sompi = take_u64_le(payload, cursor).ok_or(NoopReason::BadLength)?;
    let claim_receive_output_index = take_u16_le(payload, cursor).ok_or(NoopReason::BadLength)?;

    if expected_pool_nonce == 0 {
        return Err(NoopReason::BadNonce);
    }
    if claim_amount_sompi == 0 {
        return Err(NoopReason::InvalidAmount);
    }

    Ok(ClaimLiquidityFeesOp { asset_id, expected_pool_nonce, recipient_index, claim_amount_sompi, claim_receive_output_index })
}

fn parse_create_asset_common(
    payload: &[u8],
    cursor: &mut usize,
) -> Result<(u8, SupplyMode, u128, [u8; 32], Vec<u8>, Vec<u8>, Vec<u8>), NoopReason> {
    let decimals = take_u8(payload, cursor).ok_or(NoopReason::BadLength)?;
    if decimals > MAX_DECIMALS {
        return Err(NoopReason::BadDecimals);
    }

    let supply_mode_raw = take_u8(payload, cursor).ok_or(NoopReason::BadLength)?;
    let supply_mode = match supply_mode_raw {
        0 => SupplyMode::Uncapped,
        1 => SupplyMode::Capped,
        _ => return Err(NoopReason::BadSupplyMode),
    };
    let max_supply = take_u128_le(payload, cursor).ok_or(NoopReason::BadLength)?;
    let mint_authority_owner_id = take_32(payload, cursor).ok_or(NoopReason::BadLength)?;

    let name_len = take_u8(payload, cursor).ok_or(NoopReason::BadLength)? as usize;
    let symbol_len = take_u8(payload, cursor).ok_or(NoopReason::BadLength)? as usize;
    let metadata_len = take_u16_le(payload, cursor).ok_or(NoopReason::BadLength)? as usize;
    if name_len > MAX_NAME_LEN || symbol_len > MAX_SYMBOL_LEN || metadata_len > MAX_METADATA_LEN {
        return Err(NoopReason::BadLength);
    }

    let name = take_vec(payload, cursor, name_len).ok_or(NoopReason::BadLength)?;
    let symbol = take_vec(payload, cursor, symbol_len).ok_or(NoopReason::BadLength)?;
    let metadata = take_vec(payload, cursor, metadata_len).ok_or(NoopReason::BadLength)?;
    if std::str::from_utf8(&name).is_err() || std::str::from_utf8(&symbol).is_err() {
        return Err(NoopReason::BadUtf8);
    }

    match supply_mode {
        SupplyMode::Capped if max_supply == 0 => return Err(NoopReason::BadMaxSupply),
        SupplyMode::Uncapped if max_supply != 0 => return Err(NoopReason::BadMaxSupply),
        _ => {}
    }

    Ok((decimals, supply_mode, max_supply, mint_authority_owner_id, name, symbol, metadata))
}

fn parse_optional_platform_tag_tail(payload: &[u8], cursor: &mut usize) -> Result<Vec<u8>, NoopReason> {
    if *cursor == payload.len() {
        return Ok(Vec::new());
    }
    parse_platform_tag(payload, cursor)
}

fn parse_optional_liquidity_create_tail(payload: &[u8], cursor: &mut usize) -> Result<(Vec<u8>, u64), NoopReason> {
    if *cursor == payload.len() {
        return Ok((Vec::new(), 0));
    }
    let platform_tag = parse_platform_tag(payload, cursor)?;
    let liquidity_unlock_target_sompi = take_u64_le(payload, cursor).ok_or(NoopReason::BadLength)?;
    validate_liquidity_unlock_target(liquidity_unlock_target_sompi)?;
    Ok((platform_tag, liquidity_unlock_target_sompi))
}

fn parse_platform_tag(payload: &[u8], cursor: &mut usize) -> Result<Vec<u8>, NoopReason> {
    let platform_tag_len = take_u8(payload, cursor).ok_or(NoopReason::BadLength)? as usize;
    if platform_tag_len > MAX_PLATFORM_TAG_LEN {
        return Err(NoopReason::BadPlatformTag);
    }
    let platform_tag = take_vec(payload, cursor, platform_tag_len).ok_or(NoopReason::BadLength)?;
    if std::str::from_utf8(&platform_tag).is_err() {
        return Err(NoopReason::BadPlatformTag);
    }
    Ok(platform_tag)
}

fn validate_liquidity_unlock_target(value: u64) -> Result<(), NoopReason> {
    if value == 0 || value <= MAX_SOMPI {
        Ok(())
    } else {
        Err(NoopReason::BadLiquidityUnlockTarget)
    }
}

fn parse_recipient_address(payload: &[u8], cursor: &mut usize) -> Result<LiquidityRecipientAddress, NoopReason> {
    let address_version = take_u8(payload, cursor).ok_or(NoopReason::BadLength)?;
    let expected_len = match address_version {
        0 => 32usize,
        1 => 33usize,
        8 => 32usize,
        _ => return Err(NoopReason::RecipientEncodingInvalid),
    };
    let address_payload = take_vec(payload, cursor, expected_len).ok_or(NoopReason::BadLength)?;
    Ok(LiquidityRecipientAddress { address_version, address_payload })
}

fn recipient_order_key(recipient: &LiquidityRecipientAddress) -> (u8, &[u8]) {
    (recipient.address_version, recipient.address_payload.as_slice())
}

fn take_bytes(payload: &[u8], cursor: &mut usize, len: usize) -> Option<Vec<u8>> {
    if *cursor + len > payload.len() {
        return None;
    }
    let out = payload[*cursor..*cursor + len].to_vec();
    *cursor += len;
    Some(out)
}

fn take_vec(payload: &[u8], cursor: &mut usize, len: usize) -> Option<Vec<u8>> {
    take_bytes(payload, cursor, len)
}

fn take_u8(payload: &[u8], cursor: &mut usize) -> Option<u8> {
    if *cursor + 1 > payload.len() {
        return None;
    }
    let out = payload[*cursor];
    *cursor += 1;
    Some(out)
}

fn take_u16_le(payload: &[u8], cursor: &mut usize) -> Option<u16> {
    if *cursor + 2 > payload.len() {
        return None;
    }
    let out = u16::from_le_bytes(payload[*cursor..*cursor + 2].try_into().ok()?);
    *cursor += 2;
    Some(out)
}

fn take_u64_le(payload: &[u8], cursor: &mut usize) -> Option<u64> {
    if *cursor + 8 > payload.len() {
        return None;
    }
    let out = u64::from_le_bytes(payload[*cursor..*cursor + 8].try_into().ok()?);
    *cursor += 8;
    Some(out)
}

fn take_u128_le(payload: &[u8], cursor: &mut usize) -> Option<u128> {
    if *cursor + 16 > payload.len() {
        return None;
    }
    let out = u128::from_le_bytes(payload[*cursor..*cursor + 16].try_into().ok()?);
    *cursor += 16;
    Some(out)
}

fn take_32(payload: &[u8], cursor: &mut usize) -> Option<[u8; 32]> {
    if *cursor + 32 > payload.len() {
        return None;
    }
    let out: [u8; 32] = payload[*cursor..*cursor + 32].try_into().ok()?;
    *cursor += 32;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_header(op: u8, auth_input_index: u16, nonce: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&CRYPTIX_ATOMIC_TOKEN_MAGIC);
        bytes.push(CRYPTIX_ATOMIC_TOKEN_VERSION);
        bytes.push(op);
        bytes.push(0);
        bytes.extend_from_slice(&auth_input_index.to_le_bytes());
        bytes.extend_from_slice(&nonce.to_le_bytes());
        bytes
    }

    fn build_create_asset_payload() -> Vec<u8> {
        let mut payload = build_header(0, 3, 7);
        payload.push(8);
        payload.push(1);
        payload.extend_from_slice(&100u128.to_le_bytes());
        payload.extend_from_slice(&[7u8; 32]);
        payload.push(4);
        payload.push(3);
        payload.extend_from_slice(&5u16.to_le_bytes());
        payload.extend_from_slice(b"Gold");
        payload.extend_from_slice(b"GLD");
        payload.extend_from_slice(b"hello");
        payload
    }

    fn build_create_liquidity_payload() -> Vec<u8> {
        let mut payload = build_header(5, 3, 7);
        payload.push(LIQUIDITY_TOKEN_DECIMALS);
        payload.extend_from_slice(&crate::liquidity_math::DEFAULT_LIQUIDITY_SUPPLY_RAW.to_le_bytes());
        payload.push(4);
        payload.push(4);
        payload.extend_from_slice(&0u16.to_le_bytes());
        payload.extend_from_slice(b"Pool");
        payload.extend_from_slice(b"POOL");
        payload.extend_from_slice(&MIN_LIQUIDITY_SEED_RESERVE_SOMPI.to_le_bytes());
        payload.extend_from_slice(&0u16.to_le_bytes());
        payload.push(0);
        payload.extend_from_slice(&0u64.to_le_bytes());
        payload.extend_from_slice(&0u128.to_le_bytes());
        payload
    }

    #[test]
    fn parse_create_asset_ok() {
        let payload = build_create_asset_payload();

        let parsed = parse_atomic_token_payload(&payload).unwrap().unwrap();
        match parsed.op {
            TokenOp::CreateAsset(op) => {
                assert_eq!(op.decimals, 8);
                assert_eq!(op.supply_mode, SupplyMode::Capped);
                assert_eq!(op.max_supply, 100);
                assert_eq!(op.name, b"Gold");
                assert_eq!(op.symbol, b"GLD");
                assert_eq!(op.metadata, b"hello");
                assert!(op.platform_tag.is_empty());
            }
            _ => panic!("expected create asset"),
        }
    }

    #[test]
    fn parse_create_asset_accepts_platform_tag_at_limit() {
        let mut payload = build_create_asset_payload();
        payload.push(MAX_PLATFORM_TAG_LEN as u8);
        payload.extend(std::iter::repeat(b'x').take(MAX_PLATFORM_TAG_LEN));

        let parsed = parse_atomic_token_payload(&payload).unwrap().unwrap();
        match parsed.op {
            TokenOp::CreateAsset(op) => assert_eq!(op.platform_tag, vec![b'x'; MAX_PLATFORM_TAG_LEN]),
            _ => panic!("expected create asset"),
        }
    }

    #[test]
    fn parse_create_asset_rejects_bad_platform_tag() {
        let mut too_long = build_create_asset_payload();
        too_long.push((MAX_PLATFORM_TAG_LEN + 1) as u8);
        too_long.extend(std::iter::repeat(b'x').take(MAX_PLATFORM_TAG_LEN + 1));
        assert_eq!(parse_atomic_token_payload(&too_long).unwrap().unwrap_err(), NoopReason::BadPlatformTag);

        let mut invalid_utf8 = build_create_asset_payload();
        invalid_utf8.push(1);
        invalid_utf8.push(0xff);
        assert_eq!(parse_atomic_token_payload(&invalid_utf8).unwrap().unwrap_err(), NoopReason::BadPlatformTag);
    }

    #[test]
    fn parse_liquidity_create_lock_tail_defaults_and_accepts_max() {
        let payload = build_create_liquidity_payload();
        let parsed = parse_atomic_token_payload(&payload).unwrap().unwrap();
        match parsed.op {
            TokenOp::CreateLiquidityAsset(op) => {
                assert!(op.platform_tag.is_empty());
                assert_eq!(op.liquidity_unlock_target_sompi, 0);
            }
            _ => panic!("expected liquidity create asset"),
        }

        let mut locked = build_create_liquidity_payload();
        locked.push(6);
        locked.extend_from_slice(b"Bridge");
        locked.extend_from_slice(&MAX_SOMPI.to_le_bytes());
        let parsed = parse_atomic_token_payload(&locked).unwrap().unwrap();
        match parsed.op {
            TokenOp::CreateLiquidityAsset(op) => {
                assert_eq!(op.platform_tag, b"Bridge");
                assert_eq!(op.liquidity_unlock_target_sompi, MAX_SOMPI);
            }
            _ => panic!("expected liquidity create asset"),
        }
    }

    #[test]
    fn parse_liquidity_create_rejects_unlock_target_above_max() {
        let mut payload = build_create_liquidity_payload();
        payload.push(0);
        payload.extend_from_slice(&(MAX_SOMPI + 1).to_le_bytes());

        assert_eq!(parse_atomic_token_payload(&payload).unwrap().unwrap_err(), NoopReason::BadLiquidityUnlockTarget);
    }

    #[test]
    fn parse_non_cat_payload_returns_none() {
        let payload = b"NOPE";
        assert!(parse_atomic_token_payload(payload).is_none());
    }

    #[test]
    fn parse_invalid_flags() {
        let mut payload = build_header(1, 0, 1);
        payload[5] = 1;
        payload.extend_from_slice(&[0u8; 32]);
        payload.extend_from_slice(&[0u8; 32]);
        payload.extend_from_slice(&1u128.to_le_bytes());
        let result = parse_atomic_token_payload(&payload).unwrap();
        assert_eq!(result.unwrap_err(), NoopReason::BadFlags);
    }

    #[test]
    fn parse_buy_liquidity_rejects_zero_expected_pool_nonce() {
        let mut payload = build_header(6, 0, 1);
        payload.extend_from_slice(&[1u8; 32]); // asset_id
        payload.extend_from_slice(&0u64.to_le_bytes()); // expected_pool_nonce
        payload.extend_from_slice(&1u64.to_le_bytes()); // cpay_in_sompi
        payload.extend_from_slice(&1u128.to_le_bytes()); // min_token_out
        let result = parse_atomic_token_payload(&payload).unwrap();
        assert_eq!(result.unwrap_err(), NoopReason::BadNonce);
    }

    #[test]
    fn parse_sell_liquidity_rejects_zero_expected_pool_nonce() {
        let mut payload = build_header(7, 0, 1);
        payload.extend_from_slice(&[2u8; 32]); // asset_id
        payload.extend_from_slice(&0u64.to_le_bytes()); // expected_pool_nonce
        payload.extend_from_slice(&1u128.to_le_bytes()); // token_in
        payload.extend_from_slice(&1u64.to_le_bytes()); // min_cpay_out_sompi
        payload.extend_from_slice(&0u16.to_le_bytes()); // cpay_receive_output_index
        let result = parse_atomic_token_payload(&payload).unwrap();
        assert_eq!(result.unwrap_err(), NoopReason::BadNonce);
    }

    #[test]
    fn parse_claim_liquidity_rejects_zero_expected_pool_nonce() {
        let mut payload = build_header(8, 0, 1);
        payload.extend_from_slice(&[3u8; 32]); // asset_id
        payload.extend_from_slice(&0u64.to_le_bytes()); // expected_pool_nonce
        payload.push(0); // recipient_index
        payload.extend_from_slice(&1u64.to_le_bytes()); // claim_amount_sompi
        payload.extend_from_slice(&0u16.to_le_bytes()); // claim_receive_output_index
        let result = parse_atomic_token_payload(&payload).unwrap();
        assert_eq!(result.unwrap_err(), NoopReason::BadNonce);
    }
}
