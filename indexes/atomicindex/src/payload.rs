use serde::{Deserialize, Serialize};

pub const CRYPTIX_ATOMIC_TOKEN_MAGIC: [u8; 3] = *b"CAT";
pub const CRYPTIX_ATOMIC_TOKEN_VERSION: u8 = 1;

pub const MAX_NAME_LEN: usize = 32;
pub const MAX_SYMBOL_LEN: usize = 10;
pub const MAX_METADATA_LEN: usize = 256;
pub const MAX_DECIMALS: u8 = 18;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TokenOpCode {
    CreateAsset = 0,
    Transfer = 1,
    Mint = 2,
    Burn = 3,
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
pub enum TokenOp {
    CreateAsset(CreateAssetOp),
    Transfer(TransferOp),
    Mint(MintOp),
    Burn(BurnOp),
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
        _ => return Err(NoopReason::BadOp),
    };

    let flags = take_u8(payload, &mut cursor).ok_or(NoopReason::BadLength)?;
    if flags != 0 {
        return Err(NoopReason::BadFlags);
    }

    let auth_input_index = take_u16_le(payload, &mut cursor).ok_or(NoopReason::BadLength)?;
    let nonce = take_u64_le(payload, &mut cursor).ok_or(NoopReason::BadLength)?;

    let header = TokenOpHeader { op, auth_input_index, nonce };
    let op = match op {
        TokenOpCode::CreateAsset => TokenOp::CreateAsset(parse_create_asset_op(payload, &mut cursor)?),
        TokenOpCode::Transfer => TokenOp::Transfer(parse_transfer_op(payload, &mut cursor)?),
        TokenOpCode::Mint => TokenOp::Mint(parse_mint_op(payload, &mut cursor)?),
        TokenOpCode::Burn => TokenOp::Burn(parse_burn_op(payload, &mut cursor)?),
    };

    if cursor != payload.len() {
        return Err(NoopReason::BadLength);
    }

    Ok(ParsedTokenPayload { header, op })
}

fn parse_create_asset_op(payload: &[u8], cursor: &mut usize) -> Result<CreateAssetOp, NoopReason> {
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

    Ok(CreateAssetOp { decimals, supply_mode, max_supply, mint_authority_owner_id, name, symbol, metadata })
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

    #[test]
    fn parse_create_asset_ok() {
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

        let parsed = parse_atomic_token_payload(&payload).unwrap().unwrap();
        match parsed.op {
            TokenOp::CreateAsset(op) => {
                assert_eq!(op.decimals, 8);
                assert_eq!(op.supply_mode, SupplyMode::Capped);
                assert_eq!(op.max_supply, 100);
                assert_eq!(op.name, b"Gold");
                assert_eq!(op.symbol, b"GLD");
                assert_eq!(op.metadata, b"hello");
            }
            _ => panic!("expected create asset"),
        }
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
}
