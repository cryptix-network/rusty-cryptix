use crate::{error::Error, result::Result};
use cryptix_consensus_core::tx::TransactionId;
use cryptix_hashes::Hash;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use thiserror::Error;
use workflow_log::prelude::*;

pub const WALLET_PAYLOAD_DEFAULT_TARGET_BYTES: usize = 1024;
pub const WALLET_PAYLOAD_WARNING_THRESHOLD_BYTES: usize = 1536;
pub const WALLET_PAYLOAD_HARD_LIMIT_BYTES: usize = 2048;

pub const MESSENGER_MAGIC: [u8; 3] = *b"CXM";
pub const MESSENGER_ENVELOPE_V1_VERSION: u8 = 1;
pub const MESSENGER_RECIPIENT_TAG_LEN: usize = 16;
pub const MESSENGER_NONCE_LEN: usize = 24;
pub const MESSENGER_SENDER_DATA_LEN: usize = 32;
pub const MESSENGER_ENVELOPE_V1_HEADER_LEN: usize = 80;

const MESSENGER_MIN_CLASSIFICATION_LEN: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessengerSenderKind {
    Pubkey = 1,
    Ref = 2,
}

impl TryFrom<u8> for MessengerSenderKind {
    type Error = MessengerEnvelopeError;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Pubkey),
            2 => Ok(Self::Ref),
            _ => Err(MessengerEnvelopeError::InvalidSenderKind(value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessengerEnvelopeV1Header {
    pub msg_type: u8,
    pub flags: u8,
    pub recipient_tag: [u8; MESSENGER_RECIPIENT_TAG_LEN],
    pub nonce: [u8; MESSENGER_NONCE_LEN],
    pub sender_kind: u8,
    pub sender_len: u8,
    pub sender_data: [u8; MESSENGER_SENDER_DATA_LEN],
}

impl MessengerEnvelopeV1Header {
    pub fn new(
        msg_type: u8,
        flags: u8,
        recipient_tag: [u8; MESSENGER_RECIPIENT_TAG_LEN],
        nonce: [u8; MESSENGER_NONCE_LEN],
        sender_kind: u8,
        sender_len: u8,
        sender_data: [u8; MESSENGER_SENDER_DATA_LEN],
    ) -> std::result::Result<Self, MessengerEnvelopeError> {
        let header = Self { msg_type, flags, recipient_tag, nonce, sender_kind, sender_len, sender_data };
        validate_sender_encoding(header.sender_kind, header.sender_len, &header.sender_data)?;
        Ok(header)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessengerEnvelopeV1<'a> {
    pub header: MessengerEnvelopeV1Header,
    pub body: &'a [u8],
}

impl MessengerEnvelopeV1<'_> {
    pub fn secondary_dedup_key(&self) -> std::result::Result<Hash, MessengerEnvelopeError> {
        secondary_dedup_key(self.header.sender_kind, &self.header.sender_data, &self.header.nonce)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessengerPayloadClass<'a> {
    Raw(&'a [u8]),
    UnsupportedVersion { version: u8 },
    MessengerV1(MessengerEnvelopeV1<'a>),
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MessengerEnvelopeError {
    #[error("messenger payload too short: got {actual} bytes, expected at least {min}")]
    PayloadTooShort { actual: usize, min: usize },

    #[error("payload does not start with the CXM messenger magic prefix")]
    InvalidMagic,

    #[error("unsupported messenger envelope version {0}")]
    UnsupportedVersion(u8),

    #[error("invalid sender_kind {0}; only 1 (pubkey) and 2 (ref) are valid")]
    InvalidSenderKind(u8),

    #[error("invalid sender_len {sender_len} for sender_kind {sender_kind}")]
    InvalidSenderLength { sender_kind: u8, sender_len: u8 },

    #[error("sender_data padding must be zero for sender_kind=2")]
    NonZeroSenderPadding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessengerDedupDecision {
    EmitNewMessage,
    SuppressDuplicate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MessageChainState {
    Confirmed,
    Detached,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MessageIndexRecord {
    secondary_key: Hash,
    chain_state: MessageChainState,
}

#[derive(Debug, Default)]
pub struct MessengerDedupIndex {
    by_txid: HashMap<TransactionId, MessageIndexRecord>,
    canonical_by_secondary: HashMap<Hash, TransactionId>,
}

impl MessengerDedupIndex {
    pub fn observe_chain_message(&mut self, txid: TransactionId, secondary_key: Hash) -> MessengerDedupDecision {
        if let Some(existing) = self.by_txid.get_mut(&txid) {
            existing.chain_state = MessageChainState::Confirmed;
            self.canonical_by_secondary.entry(existing.secondary_key).or_insert(txid);
            return MessengerDedupDecision::SuppressDuplicate;
        }

        let should_emit = !self.canonical_by_secondary.contains_key(&secondary_key);
        let canonical_before = self.canonical_by_secondary.get(&secondary_key).copied();

        self.by_txid.insert(txid, MessageIndexRecord { secondary_key, chain_state: MessageChainState::Confirmed });

        match canonical_before {
            None => {
                self.canonical_by_secondary.insert(secondary_key, txid);
            }
            Some(existing_canonical_txid) => {
                let existing_state = self.by_txid.get(&existing_canonical_txid).map(|record| record.chain_state);
                if existing_state == Some(MessageChainState::Detached) {
                    self.canonical_by_secondary.insert(secondary_key, txid);
                }
            }
        }

        if should_emit {
            MessengerDedupDecision::EmitNewMessage
        } else {
            MessengerDedupDecision::SuppressDuplicate
        }
    }

    pub fn mark_detached(&mut self, txid: TransactionId) -> bool {
        let Some(record) = self.by_txid.get_mut(&txid) else {
            return false;
        };
        record.chain_state = MessageChainState::Detached;
        true
    }

    pub fn mark_confirmed(&mut self, txid: TransactionId) -> bool {
        let Some(record) = self.by_txid.get_mut(&txid) else {
            return false;
        };
        record.chain_state = MessageChainState::Confirmed;
        let canonical = self.canonical_by_secondary.get(&record.secondary_key).copied();
        if canonical.is_none() || canonical == Some(txid) {
            self.canonical_by_secondary.insert(record.secondary_key, txid);
        }
        true
    }

    pub fn canonical_txid(&self, secondary_key: &Hash) -> Option<TransactionId> {
        self.canonical_by_secondary.get(secondary_key).copied()
    }
}

pub fn validate_wallet_payload_size(payload: Option<&[u8]>) -> Result<()> {
    let Some(payload) = payload else {
        return Ok(());
    };

    let payload_len = payload.len();
    if payload_len > WALLET_PAYLOAD_HARD_LIMIT_BYTES {
        return Err(Error::WalletPayloadTooLarge { actual: payload_len, max: WALLET_PAYLOAD_HARD_LIMIT_BYTES });
    }

    if payload_len > WALLET_PAYLOAD_DEFAULT_TARGET_BYTES && payload_len <= WALLET_PAYLOAD_WARNING_THRESHOLD_BYTES {
        log_warn!(
            "wallet payload length {} bytes exceeds default target {} bytes (warning threshold {} bytes, v1 hard limit {} bytes)",
            payload_len,
            WALLET_PAYLOAD_DEFAULT_TARGET_BYTES,
            WALLET_PAYLOAD_WARNING_THRESHOLD_BYTES,
            WALLET_PAYLOAD_HARD_LIMIT_BYTES
        );
    }

    if payload_len > WALLET_PAYLOAD_WARNING_THRESHOLD_BYTES {
        log_warn!(
            "wallet payload length {} bytes exceeds warning threshold {} bytes (v1 hard limit {} bytes)",
            payload_len,
            WALLET_PAYLOAD_WARNING_THRESHOLD_BYTES,
            WALLET_PAYLOAD_HARD_LIMIT_BYTES
        );
    }

    Ok(())
}

pub fn validate_wallet_payload(payload: Option<&[u8]>) -> Result<()> {
    validate_wallet_payload_size(payload)?;

    let Some(payload) = payload else {
        return Ok(());
    };

    match classify_messenger_payload(payload) {
        Ok(MessengerPayloadClass::Raw(_)) | Ok(MessengerPayloadClass::MessengerV1(_)) => Ok(()),
        Ok(MessengerPayloadClass::UnsupportedVersion { version }) => Err(Error::WalletUnsupportedMessengerVersion { version }),
        Err(err) => Err(Error::WalletInvalidMessengerEnvelope { details: err.to_string() }),
    }
}

pub fn classify_messenger_payload(payload: &[u8]) -> std::result::Result<MessengerPayloadClass<'_>, MessengerEnvelopeError> {
    if payload.len() < MESSENGER_MAGIC.len() || payload[0..MESSENGER_MAGIC.len()] != MESSENGER_MAGIC {
        return Ok(MessengerPayloadClass::Raw(payload));
    }

    if payload.len() < MESSENGER_MIN_CLASSIFICATION_LEN {
        return Err(MessengerEnvelopeError::PayloadTooShort { actual: payload.len(), min: MESSENGER_MIN_CLASSIFICATION_LEN });
    }

    let version = payload[3];
    if version != MESSENGER_ENVELOPE_V1_VERSION {
        return Ok(MessengerPayloadClass::UnsupportedVersion { version });
    }

    parse_messenger_v1(payload).map(MessengerPayloadClass::MessengerV1)
}

pub fn parse_messenger_v1(payload: &[u8]) -> std::result::Result<MessengerEnvelopeV1<'_>, MessengerEnvelopeError> {
    if payload.len() < MESSENGER_ENVELOPE_V1_HEADER_LEN {
        return Err(MessengerEnvelopeError::PayloadTooShort { actual: payload.len(), min: MESSENGER_ENVELOPE_V1_HEADER_LEN });
    }

    if payload[0..MESSENGER_MAGIC.len()] != MESSENGER_MAGIC {
        return Err(MessengerEnvelopeError::InvalidMagic);
    }

    let version = payload[3];
    if version != MESSENGER_ENVELOPE_V1_VERSION {
        return Err(MessengerEnvelopeError::UnsupportedVersion(version));
    }

    let mut recipient_tag = [0u8; MESSENGER_RECIPIENT_TAG_LEN];
    recipient_tag.copy_from_slice(&payload[6..22]);
    let mut nonce = [0u8; MESSENGER_NONCE_LEN];
    nonce.copy_from_slice(&payload[22..46]);
    let sender_kind = payload[46];
    let sender_len = payload[47];
    let mut sender_data = [0u8; MESSENGER_SENDER_DATA_LEN];
    sender_data.copy_from_slice(&payload[48..80]);

    validate_sender_encoding(sender_kind, sender_len, &sender_data)?;

    let header = MessengerEnvelopeV1Header {
        msg_type: payload[4],
        flags: payload[5],
        recipient_tag,
        nonce,
        sender_kind,
        sender_len,
        sender_data,
    };

    Ok(MessengerEnvelopeV1 { header, body: &payload[MESSENGER_ENVELOPE_V1_HEADER_LEN..] })
}

pub fn serialize_messenger_v1(
    header: &MessengerEnvelopeV1Header,
    body: &[u8],
) -> std::result::Result<Vec<u8>, MessengerEnvelopeError> {
    validate_sender_encoding(header.sender_kind, header.sender_len, &header.sender_data)?;

    let mut payload = Vec::with_capacity(MESSENGER_ENVELOPE_V1_HEADER_LEN + body.len());
    payload.extend_from_slice(&MESSENGER_MAGIC);
    payload.push(MESSENGER_ENVELOPE_V1_VERSION);
    payload.push(header.msg_type);
    payload.push(header.flags);
    payload.extend_from_slice(&header.recipient_tag);
    payload.extend_from_slice(&header.nonce);
    payload.push(header.sender_kind);
    payload.push(header.sender_len);
    payload.extend_from_slice(&header.sender_data);
    payload.extend_from_slice(body);
    Ok(payload)
}

pub fn canonical_sender_identity(
    sender_kind: u8,
    sender_data: &[u8; MESSENGER_SENDER_DATA_LEN],
) -> std::result::Result<[u8; 1 + MESSENGER_SENDER_DATA_LEN], MessengerEnvelopeError> {
    let sender_len = match MessengerSenderKind::try_from(sender_kind)? {
        MessengerSenderKind::Pubkey => 32,
        MessengerSenderKind::Ref => 16,
    };
    validate_sender_encoding(sender_kind, sender_len, sender_data)?;

    let mut out = [0u8; 1 + MESSENGER_SENDER_DATA_LEN];
    out[0] = sender_kind;
    out[1..].copy_from_slice(sender_data);
    Ok(out)
}

pub fn secondary_dedup_key(
    sender_kind: u8,
    sender_data: &[u8; MESSENGER_SENDER_DATA_LEN],
    nonce: &[u8; MESSENGER_NONCE_LEN],
) -> std::result::Result<Hash, MessengerEnvelopeError> {
    let canonical_sender = canonical_sender_identity(sender_kind, sender_data)?;
    let mut hasher = Sha256::new();
    hasher.update(canonical_sender);
    hasher.update(nonce);
    let digest: [u8; 32] = hasher.finalize().into();
    Ok(Hash::from_bytes(digest))
}

fn validate_sender_encoding(
    sender_kind: u8,
    sender_len: u8,
    sender_data: &[u8; MESSENGER_SENDER_DATA_LEN],
) -> std::result::Result<(), MessengerEnvelopeError> {
    match MessengerSenderKind::try_from(sender_kind)? {
        MessengerSenderKind::Pubkey => {
            if sender_len != 32 {
                return Err(MessengerEnvelopeError::InvalidSenderLength { sender_kind, sender_len });
            }
        }
        MessengerSenderKind::Ref => {
            if sender_len != 16 {
                return Err(MessengerEnvelopeError::InvalidSenderLength { sender_kind, sender_len });
            }
            if sender_data[16..].iter().any(|&byte| byte != 0) {
                return Err(MessengerEnvelopeError::NonZeroSenderPadding);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_unknown_magic_as_raw() {
        let payload = [0x11, 0x22, 0x33, 0x44];
        let classified = classify_messenger_payload(&payload).unwrap();
        assert!(matches!(classified, MessengerPayloadClass::Raw(_)));
    }

    #[test]
    fn classify_unknown_version_without_best_effort_decoding() {
        let payload = [MESSENGER_MAGIC[0], MESSENGER_MAGIC[1], MESSENGER_MAGIC[2], 9, 0, 0, 0, 0];
        let classified = classify_messenger_payload(&payload).unwrap();
        assert_eq!(classified, MessengerPayloadClass::UnsupportedVersion { version: 9 });
    }

    #[test]
    fn parse_and_serialize_v1_pubkey_sender_roundtrip() {
        let header = MessengerEnvelopeV1Header::new(2, 3, [1u8; 16], [2u8; 24], 1, 32, [4u8; 32]).unwrap();
        let body = b"hello payload";

        let payload = serialize_messenger_v1(&header, body).unwrap();
        assert_eq!(payload.len(), MESSENGER_ENVELOPE_V1_HEADER_LEN + body.len());

        let parsed = parse_messenger_v1(&payload).unwrap();
        assert_eq!(parsed.header, header);
        assert_eq!(parsed.body, body);
        assert_eq!(payload.len() - MESSENGER_ENVELOPE_V1_HEADER_LEN, parsed.body.len());
    }

    #[test]
    fn parse_ref_sender_requires_zero_padding() {
        let mut sender_data = [0u8; 32];
        sender_data[..16].copy_from_slice(&[9u8; 16]);
        sender_data[31] = 1;
        let header = MessengerEnvelopeV1Header {
            msg_type: 1,
            flags: 0,
            recipient_tag: [0u8; 16],
            nonce: [0u8; 24],
            sender_kind: 2,
            sender_len: 16,
            sender_data,
        };
        let err = serialize_messenger_v1(&header, &[]).unwrap_err();
        assert_eq!(err, MessengerEnvelopeError::NonZeroSenderPadding);
    }

    #[test]
    fn sender_kind_zero_is_invalid_for_v1_parser() {
        let mut payload = vec![0u8; MESSENGER_ENVELOPE_V1_HEADER_LEN];
        payload[0..3].copy_from_slice(&MESSENGER_MAGIC);
        payload[3] = MESSENGER_ENVELOPE_V1_VERSION;
        payload[46] = 0;
        payload[47] = 0;
        let err = parse_messenger_v1(&payload).unwrap_err();
        assert_eq!(err, MessengerEnvelopeError::InvalidSenderKind(0));
    }

    #[test]
    fn dedup_key_matches_spec_bytes() {
        let sender_data = [7u8; 32];
        let nonce = [8u8; 24];
        let key_a = secondary_dedup_key(1, &sender_data, &nonce).unwrap();
        let key_b = secondary_dedup_key(1, &sender_data, &nonce).unwrap();
        assert_eq!(key_a, key_b);

        let mut nonce2 = nonce;
        nonce2[0] ^= 1;
        let key_c = secondary_dedup_key(1, &sender_data, &nonce2).unwrap();
        assert_ne!(key_a, key_c);
    }

    #[test]
    fn wallet_payload_safety_limit_applies_hard_cap() {
        let payload = vec![0u8; WALLET_PAYLOAD_HARD_LIMIT_BYTES + 1];
        let err = validate_wallet_payload_size(Some(&payload)).unwrap_err();
        assert!(matches!(err, Error::WalletPayloadTooLarge { .. }));
    }

    #[test]
    fn wallet_payload_validation_rejects_unsupported_messenger_version() {
        let payload = [MESSENGER_MAGIC[0], MESSENGER_MAGIC[1], MESSENGER_MAGIC[2], 9, 0, 0, 0, 0];
        let err = validate_wallet_payload(Some(&payload)).unwrap_err();
        assert!(matches!(err, Error::WalletUnsupportedMessengerVersion { version: 9 }));
    }

    #[test]
    fn wallet_payload_validation_rejects_invalid_messenger_v1_header() {
        let mut payload = vec![0u8; MESSENGER_ENVELOPE_V1_HEADER_LEN];
        payload[0..3].copy_from_slice(&MESSENGER_MAGIC);
        payload[3] = MESSENGER_ENVELOPE_V1_VERSION;
        payload[46] = 0; // invalid sender kind for v1
        let err = validate_wallet_payload(Some(&payload)).unwrap_err();
        assert!(matches!(err, Error::WalletInvalidMessengerEnvelope { .. }));
    }

    #[test]
    fn wallet_payload_validation_accepts_raw_non_messenger_payload() {
        let payload = [0x41, 0x42, 0x43];
        validate_wallet_payload(Some(&payload)).unwrap();
    }

    #[test]
    fn dedup_index_suppresses_rescan_duplicates() {
        let mut index = MessengerDedupIndex::default();
        let secondary = Hash::from_u64_word(42);
        let txid = TransactionId::from_u64_word(1);

        let first = index.observe_chain_message(txid, secondary);
        let second = index.observe_chain_message(txid, secondary);

        assert_eq!(first, MessengerDedupDecision::EmitNewMessage);
        assert_eq!(second, MessengerDedupDecision::SuppressDuplicate);
        assert_eq!(index.canonical_txid(&secondary), Some(txid));
    }

    #[test]
    fn dedup_index_rebinds_after_reorg_without_duplicate_event() {
        let mut index = MessengerDedupIndex::default();
        let secondary = Hash::from_u64_word(777);
        let txid_a = TransactionId::from_u64_word(100);
        let txid_b = TransactionId::from_u64_word(200);

        assert_eq!(index.observe_chain_message(txid_a, secondary), MessengerDedupDecision::EmitNewMessage);
        assert!(index.mark_detached(txid_a));

        let after_reorg = index.observe_chain_message(txid_b, secondary);
        assert_eq!(after_reorg, MessengerDedupDecision::SuppressDuplicate);
        assert_eq!(index.canonical_txid(&secondary), Some(txid_b));

        let rescan_a = index.observe_chain_message(txid_a, secondary);
        assert_eq!(rescan_a, MessengerDedupDecision::SuppressDuplicate);
        assert_eq!(index.canonical_txid(&secondary), Some(txid_b));
    }
}
