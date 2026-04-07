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
