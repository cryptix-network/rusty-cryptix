use crate::mempool::errors::{RuleError, RuleResult};
use blake2b_simd::Params as Blake2bParams;
use cryptix_consensus_core::{
    errors::tx::TxRuleError,
    subnets::SUBNETWORK_ID_PAYLOAD,
    tx::{MutableTransaction, ScriptPublicKey, Transaction},
};
use cryptix_txscript::script_class::ScriptClass;
use std::fmt::{Display, Formatter};

const CAT_MAGIC: &[u8; 3] = b"CAT";
const CAT_VERSION: u8 = 1;
const CAT_OWNER_DOMAIN: &[u8] = b"CAT_OWNER_V2";
const OWNER_AUTH_SCHEME_PUBKEY: u8 = 0;
const OWNER_AUTH_SCHEME_PUBKEY_ECDSA: u8 = 1;
const OWNER_AUTH_SCHEME_SCRIPT_HASH: u8 = 2;
pub(crate) const ATOMIC_NONCE_SCOPE_OWNER: u8 = 0;
pub(crate) const ATOMIC_NONCE_SCOPE_ASSET: u8 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum AtomicMempoolSlot {
    Nonce { owner_id: [u8; 32], scope_kind: u8, scope_id: [u8; 32], nonce: u64 },
    LiquidityPool { asset_id: [u8; 32], pool_nonce: u64 },
}

impl Display for AtomicMempoolSlot {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AtomicMempoolSlot::Nonce { owner_id, scope_kind, scope_id, nonce } => {
                let scope = match *scope_kind {
                    ATOMIC_NONCE_SCOPE_OWNER => "owner",
                    ATOMIC_NONCE_SCOPE_ASSET => "asset",
                    _ => "unknown",
                };
                write!(f, "nonce:{scope}:{}:{}:{nonce}", hex32(owner_id), hex32(scope_id))
            }
            AtomicMempoolSlot::LiquidityPool { asset_id, pool_nonce } => {
                write!(f, "liquidity-pool:{}:{pool_nonce}", hex32(asset_id))
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum ParsedAtomicNonceScope {
    Owner,
    Asset([u8; 32]),
}

#[derive(Clone, Copy, Debug)]
struct ParsedAtomicMempoolPayload {
    auth_input_index: u16,
    nonce: u64,
    nonce_scope: ParsedAtomicNonceScope,
    pool_slot: Option<([u8; 32], u64)>,
}

pub(crate) fn is_cat_transaction(tx: &Transaction) -> bool {
    tx.subnetwork_id == SUBNETWORK_ID_PAYLOAD && tx.payload.starts_with(CAT_MAGIC)
}

pub(crate) fn atomic_mempool_slots(transaction: &MutableTransaction) -> RuleResult<Vec<AtomicMempoolSlot>> {
    if !is_cat_transaction(transaction.tx.as_ref()) {
        return Ok(vec![]);
    }

    let Some(parsed) = parse_atomic_mempool_payload(transaction.tx.payload.as_slice())? else {
        return Ok(vec![]);
    };

    let auth_input_index = parsed.auth_input_index as usize;
    let auth_entry =
        transaction.entries.get(auth_input_index).and_then(|entry| entry.as_ref()).ok_or(RuleError::RejectMissingOutpoint)?;
    let owner_id = atomic_owner_id_from_script(&auth_entry.script_public_key).ok_or_else(|| {
        RuleError::RejectTxRule(TxRuleError::InvalidAtomicPayload(
            "auth input script public key is not a supported CAT owner authorization scheme".to_string(),
        ))
    })?;

    let (scope_kind, scope_id) = match parsed.nonce_scope {
        ParsedAtomicNonceScope::Owner => (ATOMIC_NONCE_SCOPE_OWNER, [0u8; 32]),
        ParsedAtomicNonceScope::Asset(asset_id) => (ATOMIC_NONCE_SCOPE_ASSET, asset_id),
    };
    let mut slots = vec![AtomicMempoolSlot::Nonce { owner_id, scope_kind, scope_id, nonce: parsed.nonce }];
    if let Some((asset_id, pool_nonce)) = parsed.pool_slot {
        slots.push(AtomicMempoolSlot::LiquidityPool { asset_id, pool_nonce });
    }
    Ok(slots)
}

pub(crate) fn atomic_mempool_liquidity_pool_slot(transaction: &Transaction) -> RuleResult<Option<AtomicMempoolSlot>> {
    if !is_cat_transaction(transaction) {
        return Ok(None);
    }

    let Some(parsed) = parse_atomic_mempool_payload(transaction.payload.as_slice())? else {
        return Ok(None);
    };

    Ok(parsed.pool_slot.map(|(asset_id, pool_nonce)| AtomicMempoolSlot::LiquidityPool { asset_id, pool_nonce }))
}

fn parse_atomic_mempool_payload(payload: &[u8]) -> RuleResult<Option<ParsedAtomicMempoolPayload>> {
    if !payload.starts_with(CAT_MAGIC) {
        return Ok(None);
    }

    let mut cursor = CAT_MAGIC.len();
    let version = take_u8(payload, &mut cursor, "truncated CAT version")?;
    if version != CAT_VERSION {
        return Err(invalid_atomic(format!("unsupported CAT version `{version}`")));
    }
    let op = take_u8(payload, &mut cursor, "truncated CAT op")?;
    if op > 8 {
        return Err(invalid_atomic(format!("unsupported CAT op `{op}`")));
    }
    let flags = take_u8(payload, &mut cursor, "truncated CAT flags")?;
    if flags != 0 {
        return Err(invalid_atomic(format!("invalid CAT flags `{flags}`")));
    }
    let auth_input_index = take_u16_le(payload, &mut cursor, "truncated CAT auth_input_index")?;
    let nonce = take_u64_le(payload, &mut cursor, "truncated CAT nonce")?;
    if nonce == 0 {
        return Err(invalid_atomic("nonce must be >= 1"));
    }

    let (nonce_scope, pool_slot) = match op {
        0 | 4 | 5 => (ParsedAtomicNonceScope::Owner, None),
        1..=3 => {
            let asset_id = take_32(payload, &mut cursor, "truncated CAT asset_id")?;
            (ParsedAtomicNonceScope::Asset(asset_id), None)
        }
        6..=8 => {
            let asset_id = take_32(payload, &mut cursor, "truncated CAT asset_id")?;
            let pool_nonce = take_u64_le(payload, &mut cursor, "truncated CAT expected_pool_nonce")?;
            if pool_nonce == 0 {
                return Err(invalid_atomic("liquidity expected_pool_nonce must be >= 1"));
            }
            (ParsedAtomicNonceScope::Asset(asset_id), Some((asset_id, pool_nonce)))
        }
        _ => unreachable!(),
    };

    Ok(Some(ParsedAtomicMempoolPayload { auth_input_index, nonce, nonce_scope, pool_slot }))
}

fn atomic_owner_id_from_script(script_public_key: &ScriptPublicKey) -> Option<[u8; 32]> {
    let (auth_scheme, canonical_pubkey_bytes) = canonical_atomic_owner_identity(script_public_key)?;
    let pubkey_len = u16::try_from(canonical_pubkey_bytes.len()).ok()?;
    let mut hasher = Blake2bParams::new().hash_length(32).to_state();
    hasher.update(CAT_OWNER_DOMAIN);
    hasher.update(&[auth_scheme]);
    hasher.update(&pubkey_len.to_le_bytes());
    hasher.update(canonical_pubkey_bytes);
    let hash = hasher.finalize();
    let mut owner_id = [0u8; 32];
    owner_id.copy_from_slice(hash.as_bytes());
    Some(owner_id)
}

fn canonical_atomic_owner_identity(script_public_key: &ScriptPublicKey) -> Option<(u8, &[u8])> {
    let script_bytes = script_public_key.script();
    match ScriptClass::from_script(script_public_key) {
        ScriptClass::PubKey if script_bytes.len() == 34 => Some((OWNER_AUTH_SCHEME_PUBKEY, &script_bytes[1..33])),
        ScriptClass::PubKeyECDSA if script_bytes.len() == 35 => Some((OWNER_AUTH_SCHEME_PUBKEY_ECDSA, &script_bytes[1..34])),
        ScriptClass::ScriptHash if script_bytes.len() == 35 => Some((OWNER_AUTH_SCHEME_SCRIPT_HASH, &script_bytes[2..34])),
        _ => None,
    }
}

fn take_bytes<'a>(payload: &'a [u8], cursor: &mut usize, len: usize, error: &'static str) -> RuleResult<&'a [u8]> {
    if (*cursor).saturating_add(len) > payload.len() {
        return Err(invalid_atomic(error));
    }
    let out = &payload[*cursor..*cursor + len];
    *cursor += len;
    Ok(out)
}

fn take_u8(payload: &[u8], cursor: &mut usize, error: &'static str) -> RuleResult<u8> {
    let out = *payload.get(*cursor).ok_or_else(|| invalid_atomic(error))?;
    *cursor += 1;
    Ok(out)
}

fn take_u16_le(payload: &[u8], cursor: &mut usize, error: &'static str) -> RuleResult<u16> {
    let bytes = take_bytes(payload, cursor, 2, error)?;
    Ok(u16::from_le_bytes(bytes.try_into().expect("slice length checked")))
}

fn take_u64_le(payload: &[u8], cursor: &mut usize, error: &'static str) -> RuleResult<u64> {
    let bytes = take_bytes(payload, cursor, 8, error)?;
    Ok(u64::from_le_bytes(bytes.try_into().expect("slice length checked")))
}

fn take_32(payload: &[u8], cursor: &mut usize, error: &'static str) -> RuleResult<[u8; 32]> {
    let bytes = take_bytes(payload, cursor, 32, error)?;
    Ok(bytes.try_into().expect("slice length checked"))
}

fn invalid_atomic(message: impl Into<String>) -> RuleError {
    RuleError::RejectTxRule(TxRuleError::InvalidAtomicPayload(message.into()))
}

fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
