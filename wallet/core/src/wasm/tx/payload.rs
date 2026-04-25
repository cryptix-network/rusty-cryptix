use crate::imports::*;
use crate::result::Result;
use crate::tx::{
    classify_messenger_payload, serialize_messenger_v1, validate_wallet_payload, MessengerEnvelopeV1Header, MessengerPayloadClass,
    MESSENGER_ENVELOPE_V1_HEADER_LEN, MESSENGER_NONCE_LEN, MESSENGER_RECIPIENT_TAG_LEN, MESSENGER_SENDER_DATA_LEN,
    WALLET_PAYLOAD_HARD_LIMIT_BYTES,
};
use cryptix_wasm_core::types::BinaryT;

const CRYPTOBOX_NONCE_BYTES: usize = 24;
const CRYPTOBOX_TAG_BYTES: usize = 16;
const CRYPTOBOX_OVERHEAD_BYTES: usize = CRYPTOBOX_NONCE_BYTES + CRYPTOBOX_TAG_BYTES;
const CAT_MAGIC: [u8; 3] = *b"CAT";
const CAT_VERSION: u8 = 1;
const CAT_FLAGS: u8 = 0;
const CAT_MAX_NAME_LEN: usize = 32;
const CAT_MAX_SYMBOL_LEN: usize = 10;
const CAT_MAX_METADATA_LEN: usize = 256;
const CAT_MAX_DECIMALS: u8 = 18;
const CAT_MAX_LIQUIDITY_RECIPIENTS: usize = 2;
const CAT_MIN_LIQUIDITY_FEE_BPS: u16 = 10;
const CAT_MAX_LIQUIDITY_FEE_BPS: u16 = 1000;

const CAT_OP_CREATE_ASSET: u8 = 0;
const CAT_OP_TRANSFER: u8 = 1;
const CAT_OP_MINT: u8 = 2;
const CAT_OP_BURN: u8 = 3;
const CAT_OP_CREATE_ASSET_WITH_MINT: u8 = 4;
const CAT_OP_CREATE_LIQUIDITY_ASSET: u8 = 5;
const CAT_OP_BUY_LIQUIDITY_EXACT_IN: u8 = 6;
const CAT_OP_SELL_LIQUIDITY_EXACT_IN: u8 = 7;
const CAT_OP_CLAIM_LIQUIDITY_FEES: u8 = 8;

#[derive(Clone)]
struct LiquidityRecipient {
    address_version: u8,
    address_payload: Vec<u8>,
}

#[wasm_bindgen(typescript_custom_section)]
const TS_MESSENGER_PAYLOAD_TYPES: &'static str = r#"
/**
 * Payload size limits and practical budgeting hints for messenger payloads.
 *
 * @category Wallet SDK
 */
export interface IMessengerPayloadLimits {
    /**
     * Wallet v1 hard cap for total payload bytes.
     */
    maxPayloadBytes: number;
    /**
     * Messenger v1 fixed header length.
     */
    headerBytes: number;
    /**
     * Maximum bytes available for messenger body (`maxPayloadBytes - headerBytes`).
     */
    maxBodyBytes: number;
    /**
     * CryptoBox ciphertext overhead in bytes (nonce + authentication tag).
     */
    cryptoboxOverheadBytes: number;
    /**
     * Maximum plaintext bytes when messenger body stores a CryptoBox ciphertext blob.
     */
    maxCryptoboxPlaintextBytes: number;
}

/**
 * Parsed messenger payload shape returned by {@link parseMessengerPayload}.
 *
 * @category Wallet SDK
 */
export interface IMessengerPayloadParseResult {
    kind: "raw" | "unsupported" | "v1";
    payloadLength: number;
    payload: Uint8Array;
    version?: number;
    msgType?: number;
    flags?: number;
    recipientTagHex?: string;
    nonceHex?: string;
    senderKind?: number;
    senderLen?: number;
    senderDataHex?: string;
    bodyLength?: number;
    body?: Uint8Array;
}
"#;

fn copy_fixed<const N: usize>(field_name: &str, bytes: &[u8]) -> Result<[u8; N]> {
    if bytes.len() != N {
        return Err(Error::custom(format!("{field_name} must be exactly {N} bytes, got {}", bytes.len())));
    }

    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn normalize_sender_data(sender_kind: u8, sender_data: &[u8]) -> Result<(u8, [u8; MESSENGER_SENDER_DATA_LEN])> {
    let mut out = [0u8; MESSENGER_SENDER_DATA_LEN];

    match sender_kind {
        1 => {
            if sender_data.len() != MESSENGER_SENDER_DATA_LEN {
                return Err(Error::custom(format!(
                    "senderData for senderKind=1 must be {} bytes, got {}",
                    MESSENGER_SENDER_DATA_LEN,
                    sender_data.len()
                )));
            }
            out.copy_from_slice(sender_data);
            Ok((32, out))
        }
        2 => {
            match sender_data.len() {
                16 => {
                    out[..16].copy_from_slice(sender_data);
                }
                MESSENGER_SENDER_DATA_LEN => {
                    out.copy_from_slice(sender_data);
                }
                _ => {
                    return Err(Error::custom(format!(
                        "senderData for senderKind=2 must be 16 or {} bytes, got {}",
                        MESSENGER_SENDER_DATA_LEN,
                        sender_data.len()
                    )));
                }
            }
            Ok((16, out))
        }
        _ => Err(Error::custom(format!("senderKind must be 1 (pubkey) or 2 (ref), got {sender_kind}"))),
    }
}

fn parse_hex_32(field_name: &str, value: &str) -> Result<[u8; 32]> {
    let normalized = value.trim().strip_prefix("0x").unwrap_or(value.trim());
    let bytes = Vec::<u8>::from_hex(normalized).map_err(|err| Error::custom(format!("{field_name} must be valid hex: {err}")))?;
    if bytes.len() != 32 {
        return Err(Error::custom(format!("{field_name} must be 32 bytes (64 hex chars), got {}", bytes.len())));
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(bytes.as_slice());
    Ok(out)
}

fn parse_u64_bigint(field_name: &str, value: BigInt) -> Result<u64> {
    value.try_into().map_err(|err| Error::custom(format!("invalid {field_name} value: {err}")))
}

fn parse_u16_from_u32(field_name: &str, value: u32) -> Result<u16> {
    u16::try_from(value).map_err(|_| Error::custom(format!("{field_name} must fit in u16")))
}

fn parse_u8_from_u32(field_name: &str, value: u32) -> Result<u8> {
    u8::try_from(value).map_err(|_| Error::custom(format!("{field_name} must fit in u8")))
}

fn parse_u128_decimal(field_name: &str, value: &str) -> Result<u128> {
    value.parse::<u128>().map_err(|err| Error::custom(format!("{field_name} must be a valid unsigned decimal string: {err}")))
}

fn parse_supply_mode(supply_mode: u32) -> Result<u8> {
    match supply_mode {
        0 | 1 => Ok(supply_mode as u8),
        _ => Err(Error::custom("supplyMode must be 0 (Uncapped) or 1 (Capped)")),
    }
}

fn build_cat_header(op_code: u8, auth_input_index: u32, nonce: u64) -> Result<Vec<u8>> {
    let auth_input_index = u16::try_from(auth_input_index).map_err(|_| Error::custom("authInputIndex must fit in u16"))?;
    if nonce == 0 {
        return Err(Error::custom("nonce must be greater than zero"));
    }

    let mut payload = Vec::with_capacity(64);
    payload.extend_from_slice(&CAT_MAGIC);
    payload.push(CAT_VERSION);
    payload.push(op_code);
    payload.push(CAT_FLAGS);
    payload.extend_from_slice(&auth_input_index.to_le_bytes());
    payload.extend_from_slice(&nonce.to_le_bytes());
    Ok(payload)
}

fn validate_token_identity_fields(name: &str, symbol: &str, metadata: &[u8], decimals: u8) -> Result<()> {
    if decimals > CAT_MAX_DECIMALS {
        return Err(Error::custom(format!("decimals must be <= {CAT_MAX_DECIMALS}")));
    }
    if name.len() > CAT_MAX_NAME_LEN {
        return Err(Error::custom(format!("name must be <= {CAT_MAX_NAME_LEN} bytes")));
    }
    if symbol.len() > CAT_MAX_SYMBOL_LEN {
        return Err(Error::custom(format!("symbol must be <= {CAT_MAX_SYMBOL_LEN} bytes")));
    }
    if metadata.len() > CAT_MAX_METADATA_LEN {
        return Err(Error::custom(format!("metadata must be <= {CAT_MAX_METADATA_LEN} bytes")));
    }
    Ok(())
}

fn push_create_asset_common(
    payload: &mut Vec<u8>,
    decimals: u8,
    supply_mode: u32,
    max_supply: u128,
    mint_authority_owner_id: &str,
    name: &str,
    symbol: &str,
    metadata: &[u8],
) -> Result<()> {
    validate_token_identity_fields(name, symbol, metadata, decimals)?;
    let supply_mode = parse_supply_mode(supply_mode)?;

    match supply_mode {
        0 if max_supply != 0 => {
            return Err(Error::custom("maxSupply must be 0 when supplyMode is Uncapped"));
        }
        1 if max_supply == 0 => {
            return Err(Error::custom("maxSupply must be > 0 when supplyMode is Capped"));
        }
        _ => {}
    }

    let mint_authority_owner_id = parse_hex_32("mintAuthorityOwnerId", mint_authority_owner_id)?;

    payload.push(decimals);
    payload.push(supply_mode);
    payload.extend_from_slice(&max_supply.to_le_bytes());
    payload.extend_from_slice(&mint_authority_owner_id);
    payload.push(name.len() as u8);
    payload.push(symbol.len() as u8);
    payload.extend_from_slice(&(metadata.len() as u16).to_le_bytes());
    payload.extend_from_slice(name.as_bytes());
    payload.extend_from_slice(symbol.as_bytes());
    payload.extend_from_slice(metadata);
    Ok(())
}

fn parse_liquidity_recipients(recipients: Array) -> Result<Vec<LiquidityRecipient>> {
    let recipient_count = recipients.length() as usize;
    if recipient_count > CAT_MAX_LIQUIDITY_RECIPIENTS {
        return Err(Error::custom(format!("recipientAddresses supports at most {CAT_MAX_LIQUIDITY_RECIPIENTS} entries")));
    }

    let mut out = Vec::with_capacity(recipient_count);
    for index in 0..recipient_count {
        let value = recipients.get(index as u32);
        let address =
            value.as_string().ok_or_else(|| Error::custom(format!("recipientAddresses[{index}] must be a string address")))?;
        let address = Address::try_from(address.as_str())
            .map_err(|err| Error::custom(format!("recipientAddresses[{index}] is not a valid address: {err}")))?;
        if address.payload.len() != address.version.public_key_len() {
            return Err(Error::custom(format!(
                "recipientAddresses[{index}] has invalid payload length {} for version {}",
                address.payload.len(),
                address.version
            )));
        }

        out.push(LiquidityRecipient { address_version: address.version as u8, address_payload: address.payload.to_vec() });
    }

    if out.len() == 2 {
        if out[0].address_version == out[1].address_version && out[0].address_payload == out[1].address_payload {
            return Err(Error::custom("recipientAddresses must not contain duplicates"));
        }
        let key_a = (out[0].address_version, out[0].address_payload.as_slice());
        let key_b = (out[1].address_version, out[1].address_payload.as_slice());
        if key_a > key_b {
            return Err(Error::custom("recipientAddresses must be in canonical lexicographic order"));
        }
    }

    Ok(out)
}

/// Returns payload hard limits and practical messenger/cryptobox budgeting.
/// @category Wallet SDK
#[wasm_bindgen(js_name = messengerPayloadLimits)]
pub fn messenger_payload_limits_js() -> Result<Object> {
    let max_payload_bytes = WALLET_PAYLOAD_HARD_LIMIT_BYTES;
    let header_bytes = MESSENGER_ENVELOPE_V1_HEADER_LEN;
    let max_body_bytes = max_payload_bytes.saturating_sub(header_bytes);
    let max_cryptobox_plaintext_bytes = max_body_bytes.saturating_sub(CRYPTOBOX_OVERHEAD_BYTES);

    let object = Object::new();
    object.set("maxPayloadBytes", &JsValue::from_f64(max_payload_bytes as f64))?;
    object.set("headerBytes", &JsValue::from_f64(header_bytes as f64))?;
    object.set("maxBodyBytes", &JsValue::from_f64(max_body_bytes as f64))?;
    object.set("cryptoboxOverheadBytes", &JsValue::from_f64(CRYPTOBOX_OVERHEAD_BYTES as f64))?;
    object.set("maxCryptoboxPlaintextBytes", &JsValue::from_f64(max_cryptobox_plaintext_bytes as f64))?;

    Ok(object)
}

/// Build a valid messenger v1 payload from header fields and body bytes.
///
/// `senderKind`:
/// - `1` = full 32-byte sender pubkey in `senderData`
/// - `2` = 16-byte sender reference (or 32-byte pre-padded data)
///
/// @category Wallet SDK
#[wasm_bindgen(js_name = serializeMessengerPayloadV1)]
pub fn serialize_messenger_payload_v1_js(
    msg_type: u8,
    flags: u8,
    recipient_tag: BinaryT,
    nonce: BinaryT,
    sender_kind: u8,
    sender_data: BinaryT,
    body: Option<BinaryT>,
) -> Result<Vec<u8>> {
    let recipient_tag = recipient_tag.try_as_vec_u8()?;
    let nonce = nonce.try_as_vec_u8()?;
    let sender_data = sender_data.try_as_vec_u8()?;
    let body = body.map(|body| body.try_as_vec_u8()).transpose()?.unwrap_or_default();

    let recipient_tag = copy_fixed::<MESSENGER_RECIPIENT_TAG_LEN>("recipientTag", &recipient_tag)?;
    let nonce = copy_fixed::<MESSENGER_NONCE_LEN>("nonce", &nonce)?;
    let (sender_len, sender_data) = normalize_sender_data(sender_kind, &sender_data)?;

    let header = MessengerEnvelopeV1Header::new(msg_type, flags, recipient_tag, nonce, sender_kind, sender_len, sender_data)
        .map_err(|err| Error::custom(err.to_string()))?;
    let payload = serialize_messenger_v1(&header, &body).map_err(|err| Error::custom(err.to_string()))?;

    validate_wallet_payload(Some(&payload))?;

    Ok(payload)
}

/// Parse an arbitrary payload and return its messenger classification plus decoded v1 fields.
/// @category Wallet SDK
#[wasm_bindgen(js_name = parseMessengerPayload)]
pub fn parse_messenger_payload_js(payload: BinaryT) -> Result<Object> {
    let payload = payload.try_as_vec_u8()?;
    let object = Object::new();

    object.set("payloadLength", &JsValue::from_f64(payload.len() as f64))?;
    object.set("payload", &js_sys::Uint8Array::from(payload.as_slice()).into())?;

    match classify_messenger_payload(&payload).map_err(|err| Error::custom(err.to_string()))? {
        MessengerPayloadClass::Raw(_) => {
            object.set("kind", &"raw".into())?;
        }
        MessengerPayloadClass::UnsupportedVersion { version } => {
            object.set("kind", &"unsupported".into())?;
            object.set("version", &JsValue::from_f64(version as f64))?;
        }
        MessengerPayloadClass::MessengerV1(envelope) => {
            object.set("kind", &"v1".into())?;
            object.set("version", &JsValue::from_f64(1.0))?;
            object.set("msgType", &JsValue::from_f64(envelope.header.msg_type as f64))?;
            object.set("flags", &JsValue::from_f64(envelope.header.flags as f64))?;
            object.set("recipientTagHex", &envelope.header.recipient_tag.as_slice().to_hex().into())?;
            object.set("nonceHex", &envelope.header.nonce.as_slice().to_hex().into())?;
            object.set("senderKind", &JsValue::from_f64(envelope.header.sender_kind as f64))?;
            object.set("senderLen", &JsValue::from_f64(envelope.header.sender_len as f64))?;
            object.set("senderDataHex", &envelope.header.sender_data.as_slice().to_hex().into())?;
            object.set("bodyLength", &JsValue::from_f64(envelope.body.len() as f64))?;
            object.set("body", &js_sys::Uint8Array::from(envelope.body).into())?;
        }
    }

    Ok(object)
}

#[wasm_bindgen(typescript_custom_section)]
const TS_ATOMIC_TOKEN_PAYLOAD_TYPES: &'static str = r#"
/**
 * CAT payload constants shared by token-payload serializer helpers.
 *
 * @category Wallet SDK
 */
export interface IAtomicTokenPayloadConstants {
    maxNameBytes: number;
    maxSymbolBytes: number;
    maxMetadataBytes: number;
    maxDecimals: number;
    maxLiquidityRecipients: number;
    minLiquidityFeeBps: number;
    maxLiquidityFeeBps: number;
}
"#;

/// Return CAT payload constants used by serializer helpers.
/// @category Wallet SDK
#[wasm_bindgen(js_name = atomicTokenPayloadConstants)]
pub fn atomic_token_payload_constants_js() -> Result<Object> {
    let object = Object::new();
    object.set("maxNameBytes", &JsValue::from_f64(CAT_MAX_NAME_LEN as f64))?;
    object.set("maxSymbolBytes", &JsValue::from_f64(CAT_MAX_SYMBOL_LEN as f64))?;
    object.set("maxMetadataBytes", &JsValue::from_f64(CAT_MAX_METADATA_LEN as f64))?;
    object.set("maxDecimals", &JsValue::from_f64(CAT_MAX_DECIMALS as f64))?;
    object.set("maxLiquidityRecipients", &JsValue::from_f64(CAT_MAX_LIQUIDITY_RECIPIENTS as f64))?;
    object.set("minLiquidityFeeBps", &JsValue::from_f64(CAT_MIN_LIQUIDITY_FEE_BPS as f64))?;
    object.set("maxLiquidityFeeBps", &JsValue::from_f64(CAT_MAX_LIQUIDITY_FEE_BPS as f64))?;
    Ok(object)
}

/// Serialize CAT create-asset payload (op=0).
/// @category Wallet SDK
#[wasm_bindgen(js_name = serializeAtomicTokenCreateAssetPayload)]
pub fn serialize_atomic_token_create_asset_payload_js(
    auth_input_index: u32,
    nonce: BigInt,
    decimals: u8,
    supply_mode: u32,
    max_supply: String,
    mint_authority_owner_id: String,
    name: String,
    symbol: String,
    metadata: BinaryT,
) -> Result<Vec<u8>> {
    let nonce = parse_u64_bigint("nonce", nonce)?;
    let max_supply = parse_u128_decimal("maxSupply", max_supply.as_str())?;
    let metadata = metadata.try_as_vec_u8()?;

    let mut payload = build_cat_header(CAT_OP_CREATE_ASSET, auth_input_index, nonce)?;
    push_create_asset_common(
        &mut payload,
        decimals,
        supply_mode,
        max_supply,
        mint_authority_owner_id.as_str(),
        name.as_str(),
        symbol.as_str(),
        metadata.as_slice(),
    )?;
    Ok(payload)
}

/// Serialize CAT transfer payload (op=1).
/// @category Wallet SDK
#[wasm_bindgen(js_name = serializeAtomicTokenTransferPayload)]
pub fn serialize_atomic_token_transfer_payload_js(
    auth_input_index: u32,
    nonce: BigInt,
    asset_id: String,
    to_owner_id: String,
    amount: String,
) -> Result<Vec<u8>> {
    let nonce = parse_u64_bigint("nonce", nonce)?;
    let amount = parse_u128_decimal("amount", amount.as_str())?;
    if amount == 0 {
        return Err(Error::custom("amount must be greater than zero"));
    }

    let asset_id = parse_hex_32("assetId", asset_id.as_str())?;
    let to_owner_id = parse_hex_32("toOwnerId", to_owner_id.as_str())?;

    let mut payload = build_cat_header(CAT_OP_TRANSFER, auth_input_index, nonce)?;
    payload.extend_from_slice(&asset_id);
    payload.extend_from_slice(&to_owner_id);
    payload.extend_from_slice(&amount.to_le_bytes());
    Ok(payload)
}

/// Serialize CAT mint payload (op=2).
/// @category Wallet SDK
#[wasm_bindgen(js_name = serializeAtomicTokenMintPayload)]
pub fn serialize_atomic_token_mint_payload_js(
    auth_input_index: u32,
    nonce: BigInt,
    asset_id: String,
    to_owner_id: String,
    amount: String,
) -> Result<Vec<u8>> {
    let nonce = parse_u64_bigint("nonce", nonce)?;
    let amount = parse_u128_decimal("amount", amount.as_str())?;
    if amount == 0 {
        return Err(Error::custom("amount must be greater than zero"));
    }

    let asset_id = parse_hex_32("assetId", asset_id.as_str())?;
    let to_owner_id = parse_hex_32("toOwnerId", to_owner_id.as_str())?;

    let mut payload = build_cat_header(CAT_OP_MINT, auth_input_index, nonce)?;
    payload.extend_from_slice(&asset_id);
    payload.extend_from_slice(&to_owner_id);
    payload.extend_from_slice(&amount.to_le_bytes());
    Ok(payload)
}

/// Serialize CAT burn payload (op=3).
/// @category Wallet SDK
#[wasm_bindgen(js_name = serializeAtomicTokenBurnPayload)]
pub fn serialize_atomic_token_burn_payload_js(
    auth_input_index: u32,
    nonce: BigInt,
    asset_id: String,
    amount: String,
) -> Result<Vec<u8>> {
    let nonce = parse_u64_bigint("nonce", nonce)?;
    let amount = parse_u128_decimal("amount", amount.as_str())?;
    if amount == 0 {
        return Err(Error::custom("amount must be greater than zero"));
    }

    let asset_id = parse_hex_32("assetId", asset_id.as_str())?;
    let mut payload = build_cat_header(CAT_OP_BURN, auth_input_index, nonce)?;
    payload.extend_from_slice(&asset_id);
    payload.extend_from_slice(&amount.to_le_bytes());
    Ok(payload)
}

/// Serialize CAT create-asset-with-mint payload (op=4).
/// @category Wallet SDK
#[wasm_bindgen(js_name = serializeAtomicTokenCreateAssetWithMintPayload)]
pub fn serialize_atomic_token_create_asset_with_mint_payload_js(
    auth_input_index: u32,
    nonce: BigInt,
    decimals: u8,
    supply_mode: u32,
    max_supply: String,
    mint_authority_owner_id: String,
    name: String,
    symbol: String,
    metadata: BinaryT,
    initial_mint_amount: String,
    initial_mint_to_owner_id: String,
) -> Result<Vec<u8>> {
    let nonce = parse_u64_bigint("nonce", nonce)?;
    let max_supply = parse_u128_decimal("maxSupply", max_supply.as_str())?;
    let metadata = metadata.try_as_vec_u8()?;
    let initial_mint_amount = parse_u128_decimal("initialMintAmount", initial_mint_amount.as_str())?;
    let initial_mint_to_owner_id = parse_hex_32("initialMintToOwnerId", initial_mint_to_owner_id.as_str())?;

    if initial_mint_amount == 0 && initial_mint_to_owner_id != [0u8; 32] {
        return Err(Error::custom("initialMintToOwnerId must be zeroed when initialMintAmount is 0"));
    }
    if initial_mint_amount > 0 && initial_mint_to_owner_id == [0u8; 32] {
        return Err(Error::custom("initialMintToOwnerId must be non-zero when initialMintAmount is > 0"));
    }

    let mut payload = build_cat_header(CAT_OP_CREATE_ASSET_WITH_MINT, auth_input_index, nonce)?;
    push_create_asset_common(
        &mut payload,
        decimals,
        supply_mode,
        max_supply,
        mint_authority_owner_id.as_str(),
        name.as_str(),
        symbol.as_str(),
        metadata.as_slice(),
    )?;
    payload.extend_from_slice(&initial_mint_amount.to_le_bytes());
    payload.extend_from_slice(&initial_mint_to_owner_id);
    Ok(payload)
}

/// Serialize CAT create-liquidity-asset payload (op=5).
/// @category Wallet SDK
#[wasm_bindgen(js_name = serializeAtomicTokenCreateLiquidityAssetPayload)]
pub fn serialize_atomic_token_create_liquidity_asset_payload_js(
    auth_input_index: u32,
    nonce: BigInt,
    decimals: u8,
    max_supply: String,
    name: String,
    symbol: String,
    metadata: BinaryT,
    seed_reserve_sompi: BigInt,
    fee_bps: u32,
    recipient_addresses: Array,
    launch_buy_sompi: BigInt,
    launch_buy_min_token_out: String,
) -> Result<Vec<u8>> {
    let nonce = parse_u64_bigint("nonce", nonce)?;
    let max_supply = parse_u128_decimal("maxSupply", max_supply.as_str())?;
    if max_supply == 0 {
        return Err(Error::custom("maxSupply must be greater than zero"));
    }

    let metadata = metadata.try_as_vec_u8()?;
    validate_token_identity_fields(name.as_str(), symbol.as_str(), metadata.as_slice(), decimals)?;

    let seed_reserve_sompi = parse_u64_bigint("seedReserveSompi", seed_reserve_sompi)?;
    if seed_reserve_sompi == 0 {
        return Err(Error::custom("seedReserveSompi must be greater than zero"));
    }

    let fee_bps = parse_u16_from_u32("feeBps", fee_bps)?;
    if !(fee_bps == 0 || (CAT_MIN_LIQUIDITY_FEE_BPS..=CAT_MAX_LIQUIDITY_FEE_BPS).contains(&fee_bps)) {
        return Err(Error::custom(format!("feeBps must be 0 or between {CAT_MIN_LIQUIDITY_FEE_BPS} and {CAT_MAX_LIQUIDITY_FEE_BPS}")));
    }

    let recipients = parse_liquidity_recipients(recipient_addresses)?;
    if fee_bps == 0 && !recipients.is_empty() {
        return Err(Error::custom("recipientAddresses must be empty when feeBps is 0"));
    }
    if fee_bps > 0 && recipients.is_empty() {
        return Err(Error::custom("recipientAddresses must contain 1 or 2 entries when feeBps is > 0"));
    }

    let launch_buy_sompi = parse_u64_bigint("launchBuySompi", launch_buy_sompi)?;
    let launch_buy_min_token_out = parse_u128_decimal("launchBuyMinTokenOut", launch_buy_min_token_out.as_str())?;
    if launch_buy_sompi == 0 && launch_buy_min_token_out != 0 {
        return Err(Error::custom("launchBuyMinTokenOut must be 0 when launchBuySompi is 0"));
    }
    if launch_buy_sompi > 0 && launch_buy_min_token_out == 0 {
        return Err(Error::custom("launchBuyMinTokenOut must be > 0 when launchBuySompi is > 0"));
    }

    let mut payload = build_cat_header(CAT_OP_CREATE_LIQUIDITY_ASSET, auth_input_index, nonce)?;
    payload.push(decimals);
    payload.extend_from_slice(&max_supply.to_le_bytes());
    payload.push(name.len() as u8);
    payload.push(symbol.len() as u8);
    payload.extend_from_slice(&(metadata.len() as u16).to_le_bytes());
    payload.extend_from_slice(name.as_bytes());
    payload.extend_from_slice(symbol.as_bytes());
    payload.extend_from_slice(metadata.as_slice());
    payload.extend_from_slice(&seed_reserve_sompi.to_le_bytes());
    payload.extend_from_slice(&fee_bps.to_le_bytes());
    payload.push(recipients.len() as u8);
    for recipient in recipients {
        payload.push(recipient.address_version);
        payload.extend_from_slice(recipient.address_payload.as_slice());
    }
    payload.extend_from_slice(&launch_buy_sompi.to_le_bytes());
    payload.extend_from_slice(&launch_buy_min_token_out.to_le_bytes());
    Ok(payload)
}

/// Serialize CAT buy-liquidity-exact-in payload (op=6).
/// @category Wallet SDK
#[wasm_bindgen(js_name = serializeAtomicTokenBuyLiquidityExactInPayload)]
pub fn serialize_atomic_token_buy_liquidity_exact_in_payload_js(
    auth_input_index: u32,
    nonce: BigInt,
    asset_id: String,
    expected_pool_nonce: BigInt,
    cpay_in_sompi: BigInt,
    min_token_out: String,
) -> Result<Vec<u8>> {
    let nonce = parse_u64_bigint("nonce", nonce)?;
    let asset_id = parse_hex_32("assetId", asset_id.as_str())?;
    let expected_pool_nonce = parse_u64_bigint("expectedPoolNonce", expected_pool_nonce)?;
    if expected_pool_nonce == 0 {
        return Err(Error::custom("expectedPoolNonce must be greater than zero"));
    }
    let cpay_in_sompi = parse_u64_bigint("cpayInSompi", cpay_in_sompi)?;
    if cpay_in_sompi == 0 {
        return Err(Error::custom("cpayInSompi must be greater than zero"));
    }
    let min_token_out = parse_u128_decimal("minTokenOut", min_token_out.as_str())?;
    if min_token_out == 0 {
        return Err(Error::custom("minTokenOut must be greater than zero"));
    }

    let mut payload = build_cat_header(CAT_OP_BUY_LIQUIDITY_EXACT_IN, auth_input_index, nonce)?;
    payload.extend_from_slice(&asset_id);
    payload.extend_from_slice(&expected_pool_nonce.to_le_bytes());
    payload.extend_from_slice(&cpay_in_sompi.to_le_bytes());
    payload.extend_from_slice(&min_token_out.to_le_bytes());
    Ok(payload)
}

/// Serialize CAT sell-liquidity-exact-in payload (op=7).
/// @category Wallet SDK
#[wasm_bindgen(js_name = serializeAtomicTokenSellLiquidityExactInPayload)]
pub fn serialize_atomic_token_sell_liquidity_exact_in_payload_js(
    auth_input_index: u32,
    nonce: BigInt,
    asset_id: String,
    expected_pool_nonce: BigInt,
    token_in: String,
    min_cpay_out_sompi: BigInt,
    cpay_receive_output_index: u32,
) -> Result<Vec<u8>> {
    let nonce = parse_u64_bigint("nonce", nonce)?;
    let asset_id = parse_hex_32("assetId", asset_id.as_str())?;
    let expected_pool_nonce = parse_u64_bigint("expectedPoolNonce", expected_pool_nonce)?;
    if expected_pool_nonce == 0 {
        return Err(Error::custom("expectedPoolNonce must be greater than zero"));
    }
    let token_in = parse_u128_decimal("tokenIn", token_in.as_str())?;
    if token_in == 0 {
        return Err(Error::custom("tokenIn must be greater than zero"));
    }
    let min_cpay_out_sompi = parse_u64_bigint("minCpayOutSompi", min_cpay_out_sompi)?;
    if min_cpay_out_sompi == 0 {
        return Err(Error::custom("minCpayOutSompi must be greater than zero"));
    }
    let cpay_receive_output_index = parse_u16_from_u32("cpayReceiveOutputIndex", cpay_receive_output_index)?;

    let mut payload = build_cat_header(CAT_OP_SELL_LIQUIDITY_EXACT_IN, auth_input_index, nonce)?;
    payload.extend_from_slice(&asset_id);
    payload.extend_from_slice(&expected_pool_nonce.to_le_bytes());
    payload.extend_from_slice(&token_in.to_le_bytes());
    payload.extend_from_slice(&min_cpay_out_sompi.to_le_bytes());
    payload.extend_from_slice(&cpay_receive_output_index.to_le_bytes());
    Ok(payload)
}

/// Serialize CAT claim-liquidity-fees payload (op=8).
/// @category Wallet SDK
#[wasm_bindgen(js_name = serializeAtomicTokenClaimLiquidityFeesPayload)]
pub fn serialize_atomic_token_claim_liquidity_fees_payload_js(
    auth_input_index: u32,
    nonce: BigInt,
    asset_id: String,
    expected_pool_nonce: BigInt,
    recipient_index: u32,
    claim_amount_sompi: BigInt,
    claim_receive_output_index: u32,
) -> Result<Vec<u8>> {
    let nonce = parse_u64_bigint("nonce", nonce)?;
    let asset_id = parse_hex_32("assetId", asset_id.as_str())?;
    let expected_pool_nonce = parse_u64_bigint("expectedPoolNonce", expected_pool_nonce)?;
    if expected_pool_nonce == 0 {
        return Err(Error::custom("expectedPoolNonce must be greater than zero"));
    }
    let recipient_index = parse_u8_from_u32("recipientIndex", recipient_index)?;
    let claim_amount_sompi = parse_u64_bigint("claimAmountSompi", claim_amount_sompi)?;
    if claim_amount_sompi == 0 {
        return Err(Error::custom("claimAmountSompi must be greater than zero"));
    }
    let claim_receive_output_index = parse_u16_from_u32("claimReceiveOutputIndex", claim_receive_output_index)?;

    let mut payload = build_cat_header(CAT_OP_CLAIM_LIQUIDITY_FEES, auth_input_index, nonce)?;
    payload.extend_from_slice(&asset_id);
    payload.extend_from_slice(&expected_pool_nonce.to_le_bytes());
    payload.push(recipient_index);
    payload.extend_from_slice(&claim_amount_sompi.to_le_bytes());
    payload.extend_from_slice(&claim_receive_output_index.to_le_bytes());
    Ok(payload)
}
