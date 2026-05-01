use crate::constants::{MAX_SOMPI, SEQUENCE_LOCK_TIME_DISABLED, SEQUENCE_LOCK_TIME_MASK, SOMPI_PER_CRYPTIX};
use blake2b_simd::Params as Blake2bParams;
use cryptix_consensus_core::{
    hashing::sighash::SigHashReusedValues,
    mass::Kip9Version,
    tx::{ScriptPublicKey, TransactionInput, VerifiableTransaction},
};
use cryptix_core::warn;
use cryptix_txscript::{get_sig_op_count, script_class::ScriptClass, TxScriptEngine};
use cryptix_txscript_errors::TxScriptError;

use super::{
    errors::{TxResult, TxRuleError},
    TransactionValidator,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TxValidationFlags {
    /// Perform full validation including script verification
    Full,

    /// Perform fee and sequence/maturity validations but skip script checks. This is usually
    /// an optimization to be applied when it is known that scripts were already checked
    SkipScriptChecks,

    /// When validating mempool transactions, we just set this value ourselves
    SkipMassCheck,
}

impl TransactionValidator {
    pub fn validate_populated_transaction_and_get_fee(
        &self,
        tx: &impl VerifiableTransaction,
        pov_daa_score: u64,
        flags: TxValidationFlags,
        mass_and_feerate_threshold: Option<(u64, f64)>,
    ) -> TxResult<u64> {
        self.check_transaction_coinbase_maturity(tx, pov_daa_score)?;
        self.check_atomic_payload_context(tx, pov_daa_score)?;
        let total_in = self.check_transaction_input_amounts(tx)?;
        let total_out = Self::check_transaction_output_values(tx, total_in)?;
        let fee = total_in - total_out;
        if flags != TxValidationFlags::SkipMassCheck && pov_daa_score > self.storage_mass_activation_daa_score {
            // Storage mass hardfork was activated
            self.check_mass_commitment(tx)?;

            if pov_daa_score < self.storage_mass_activation_daa_score + 10 && self.storage_mass_activation_daa_score > 0 {
                warn!("--------- Storage mass hardfork was activated successfully!!! --------- (DAA score: {})", pov_daa_score);
            }
        }
        Self::check_sequence_lock(tx, pov_daa_score)?;

        // The following call is not a consensus check (it could not be one in the first place since it uses floating number)
        // but rather a mempool Replace by Fee validation rule. It was placed here purposely for avoiding unneeded script checks.
        Self::check_feerate_threshold(fee, mass_and_feerate_threshold)?;

        match flags {
            TxValidationFlags::Full | TxValidationFlags::SkipMassCheck => {
                Self::check_sig_op_counts(tx)?;
                self.check_scripts(tx)?;
            }
            TxValidationFlags::SkipScriptChecks => {}
        }
        Ok(fee)
    }

    fn check_atomic_payload_context(&self, tx: &impl VerifiableTransaction, pov_daa_score: u64) -> TxResult<()> {
        if pov_daa_score < self.payload_hf_activation_daa_score {
            return Ok(());
        }

        let tx_ref = tx.tx();
        if !tx_ref.subnetwork_id.is_payload() || tx_ref.payload.is_empty() {
            return Ok(());
        }

        let payload = tx_ref.payload.as_slice();
        if payload.len() < CAT_MAGIC.len() || payload[..CAT_MAGIC.len()] != CAT_MAGIC {
            return Ok(());
        }

        let parsed_payload = parse_atomic_payload(payload).map_err(TxRuleError::InvalidAtomicPayload)?;
        let Some(parsed_payload) = parsed_payload else {
            return Ok(());
        };
        let auth_input_index = parsed_payload.auth_input_index;

        let auth_input_index = auth_input_index as usize;
        let (_, auth_entry) = tx.populated_inputs().nth(auth_input_index).ok_or_else(|| {
            TxRuleError::InvalidAtomicPayload(format!(
                "auth_input_index `{auth_input_index}` has no populated UTXO entry in contextual validation"
            ))
        })?;
        if atomic_owner_id_from_script(&auth_entry.script_public_key).is_none() {
            return Err(TxRuleError::InvalidAtomicPayload(
                "auth input script public key is not a supported CAT owner authorization scheme (expected PubKey, PubKeyECDSA, or ScriptHash)"
                    .to_string(),
            ));
        }

        Ok(())
    }

    fn check_feerate_threshold(fee: u64, mass_and_feerate_threshold: Option<(u64, f64)>) -> TxResult<()> {
        // An actual check can only occur if some mass and threshold are provided,
        // otherwise, the check does not verify anything and exits successfully.
        if let Some((contextual_mass, feerate_threshold)) = mass_and_feerate_threshold {
            assert!(contextual_mass > 0);
            if fee as f64 / contextual_mass as f64 <= feerate_threshold {
                return Err(TxRuleError::FeerateTooLow);
            }
        }
        Ok(())
    }

    fn check_transaction_coinbase_maturity(&self, tx: &impl VerifiableTransaction, pov_daa_score: u64) -> TxResult<()> {
        if let Some((index, (input, entry))) = tx
            .populated_inputs()
            .enumerate()
            .find(|(_, (_, entry))| entry.is_coinbase && entry.block_daa_score + self.coinbase_maturity > pov_daa_score)
        {
            return Err(TxRuleError::ImmatureCoinbaseSpend(
                index,
                input.previous_outpoint,
                entry.block_daa_score,
                pov_daa_score,
                self.coinbase_maturity,
            ));
        }

        Ok(())
    }

    fn check_transaction_input_amounts(&self, tx: &impl VerifiableTransaction) -> TxResult<u64> {
        let mut total: u64 = 0;
        for (_, entry) in tx.populated_inputs() {
            if let Some(new_total) = total.checked_add(entry.amount) {
                total = new_total
            } else {
                return Err(TxRuleError::InputAmountOverflow);
            }

            if total > MAX_SOMPI {
                return Err(TxRuleError::InputAmountTooHigh);
            }
        }

        Ok(total)
    }

    fn check_transaction_output_values(tx: &impl VerifiableTransaction, total_in: u64) -> TxResult<u64> {
        // There's no need to check for overflow here because it was already checked by check_transaction_output_value_ranges
        let total_out: u64 = tx.outputs().iter().map(|out| out.value).sum();
        if total_in < total_out {
            return Err(TxRuleError::SpendTooHigh(total_out, total_in));
        }

        Ok(total_out)
    }

    fn check_mass_commitment(&self, tx: &impl VerifiableTransaction) -> TxResult<()> {
        let calculated_contextual_mass =
            self.mass_calculator.calc_tx_overall_mass(tx, None, Kip9Version::Alpha).ok_or(TxRuleError::MassIncomputable)?;
        let committed_contextual_mass = tx.tx().mass();
        if committed_contextual_mass != calculated_contextual_mass {
            return Err(TxRuleError::WrongMass(calculated_contextual_mass, committed_contextual_mass));
        }
        Ok(())
    }

    fn check_sequence_lock(tx: &impl VerifiableTransaction, pov_daa_score: u64) -> TxResult<()> {
        let pov_daa_score: i64 = pov_daa_score as i64;
        if tx.populated_inputs().filter(|(input, _)| input.sequence & SEQUENCE_LOCK_TIME_DISABLED != SEQUENCE_LOCK_TIME_DISABLED).any(
            |(input, entry)| {
                // Given a sequence number, we apply the relative time lock
                // mask in order to obtain the time lock delta required before
                // this input can be spent.
                let relative_lock = (input.sequence & SEQUENCE_LOCK_TIME_MASK) as i64;

                // The relative lock-time for this input is expressed
                // in blocks so we calculate the relative offset from
                // the input's DAA score as its converted absolute
                // lock-time. We subtract one from the relative lock in
                // order to maintain the original lockTime semantics.
                //
                // Note: in the cryptixd codebase there's a use in i64 in order to use the -1 value
                // as None. Here it's not needed, but we still use it to avoid breaking consensus.
                let lock_daa_score = entry.block_daa_score as i64 + relative_lock - 1;

                lock_daa_score >= pov_daa_score
            },
        ) {
            return Err(TxRuleError::SequenceLockConditionsAreNotMet);
        }
        Ok(())
    }

    fn check_sig_op_counts<T: VerifiableTransaction>(tx: &T) -> TxResult<()> {
        for (i, (input, entry)) in tx.populated_inputs().enumerate() {
            let calculated = get_sig_op_count::<T>(&input.signature_script, &entry.script_public_key);
            if calculated != input.sig_op_count as u64 {
                return Err(TxRuleError::WrongSigOpCount(i, input.sig_op_count as u64, calculated));
            }
        }
        Ok(())
    }

    pub fn check_scripts(&self, tx: &impl VerifiableTransaction) -> TxResult<()> {
        let mut reused_values = SigHashReusedValues::new();
        for (i, (input, entry)) in tx.populated_inputs().enumerate() {
            let mut engine = TxScriptEngine::from_transaction_input(tx, input, i, entry, &mut reused_values, &self.sig_cache)
                .map_err(|err| map_script_err(err, input))?;
            engine.execute().map_err(|err| map_script_err(err, input))?;
        }

        Ok(())
    }
}

fn map_script_err(script_err: TxScriptError, input: &TransactionInput) -> TxRuleError {
    if input.signature_script.is_empty() {
        TxRuleError::SignatureEmpty(script_err)
    } else {
        TxRuleError::SignatureInvalid(script_err)
    }
}

pub(crate) const CAT_MAGIC: [u8; 3] = *b"CAT";
const CAT_VERSION: u8 = 1;
const CAT_CURRENT_TOKEN_VERSION: u8 = 1;
const CAT_CURRENT_LIQUIDITY_CURVE_VERSION: u8 = 1;
const CAT_MAX_TOKEN_VERSION: u8 = 99;
const CAT_MAX_LIQUIDITY_CURVE_VERSION: u8 = 99;
const CAT_OWNER_DOMAIN: &[u8] = b"CAT_OWNER_V2";
const OWNER_AUTH_SCHEME_PUBKEY: u8 = 0;
const OWNER_AUTH_SCHEME_PUBKEY_ECDSA: u8 = 1;
const OWNER_AUTH_SCHEME_SCRIPT_HASH: u8 = 2;
const CAT_MAX_NAME_LEN: usize = 32;
const CAT_MAX_SYMBOL_LEN: usize = 10;
const CAT_MAX_METADATA_LEN: usize = 256;
const CAT_MAX_PLATFORM_TAG_LEN: usize = 50;
const CAT_MAX_DECIMALS: u8 = 18;
const CAT_MAX_LIQUIDITY_RECIPIENTS: usize = 2;
const CAT_MIN_LIQUIDITY_FEE_BPS: u16 = 10;
const CAT_MAX_LIQUIDITY_FEE_BPS: u16 = 1000;
const CAT_LIQUIDITY_TOKEN_DECIMALS: u8 = 0;
const CAT_MIN_LIQUIDITY_SUPPLY_RAW: u128 = 100_000;
const CAT_MAX_LIQUIDITY_SUPPLY_RAW: u128 = 10_000_000;
const CAT_MIN_LIQUIDITY_SEED_RESERVE_SOMPI: u64 = SOMPI_PER_CRYPTIX;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AtomicPayloadSupplyMode {
    Uncapped,
    Capped,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AtomicPayloadOp {
    CreateAsset {
        token_version: u8,
        decimals: u8,
        supply_mode: AtomicPayloadSupplyMode,
        max_supply: u128,
        mint_authority_owner_id: [u8; 32],
        name: Vec<u8>,
        symbol: Vec<u8>,
        metadata: Vec<u8>,
        platform_tag: Vec<u8>,
    },
    Transfer {
        asset_id: [u8; 32],
        to_owner_id: [u8; 32],
        amount: u128,
    },
    Mint {
        asset_id: [u8; 32],
        to_owner_id: [u8; 32],
        amount: u128,
    },
    Burn {
        asset_id: [u8; 32],
        amount: u128,
    },
    CreateAssetWithMint {
        token_version: u8,
        decimals: u8,
        supply_mode: AtomicPayloadSupplyMode,
        max_supply: u128,
        mint_authority_owner_id: [u8; 32],
        name: Vec<u8>,
        symbol: Vec<u8>,
        metadata: Vec<u8>,
        initial_mint_amount: u128,
        initial_mint_to_owner_id: [u8; 32],
        platform_tag: Vec<u8>,
    },
    CreateLiquidityAsset {
        token_version: u8,
        curve_version: u8,
        decimals: u8,
        max_supply: u128,
        name: Vec<u8>,
        symbol: Vec<u8>,
        metadata: Vec<u8>,
        seed_reserve_sompi: u64,
        fee_bps: u16,
        recipients: Vec<AtomicPayloadRecipientAddress>,
        launch_buy_sompi: u64,
        launch_buy_min_token_out: u128,
        platform_tag: Vec<u8>,
        liquidity_unlock_target_sompi: u64,
    },
    BuyLiquidityExactIn {
        asset_id: [u8; 32],
        expected_pool_nonce: u64,
        cpay_in_sompi: u64,
        min_token_out: u128,
    },
    SellLiquidityExactIn {
        asset_id: [u8; 32],
        expected_pool_nonce: u64,
        token_in: u128,
        min_cpay_out_sompi: u64,
        cpay_receive_output_index: u16,
    },
    ClaimLiquidityFees {
        asset_id: [u8; 32],
        expected_pool_nonce: u64,
        recipient_index: u8,
        claim_amount_sompi: u64,
        claim_receive_output_index: u16,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AtomicPayloadRecipientAddress {
    pub address_version: u8,
    pub address_payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ParsedAtomicPayload {
    pub auth_input_index: u16,
    pub nonce: u64,
    pub op: AtomicPayloadOp,
}

pub(crate) fn parse_atomic_payload(payload: &[u8]) -> Result<Option<ParsedAtomicPayload>, String> {
    if payload.len() < CAT_MAGIC.len() || payload[..CAT_MAGIC.len()] != CAT_MAGIC {
        return Ok(None);
    }

    let mut cursor = 0usize;
    let magic = take_bytes(payload, &mut cursor, CAT_MAGIC.len()).ok_or_else(|| "truncated CAT magic".to_string())?;
    if magic != CAT_MAGIC {
        return Err("invalid CAT magic".to_string());
    }

    let version = take_u8(payload, &mut cursor).ok_or_else(|| "truncated CAT version".to_string())?;
    if version != CAT_VERSION {
        return Err(format!("unsupported CAT version `{version}`"));
    }

    let op = take_u8(payload, &mut cursor).ok_or_else(|| "truncated CAT op".to_string())?;
    if op > 8 {
        return Err(format!("unsupported CAT op `{op}`"));
    }

    let flags = take_u8(payload, &mut cursor).ok_or_else(|| "truncated CAT flags".to_string())?;
    if flags != 0 {
        return Err(format!("invalid CAT flags `{flags}`"));
    }

    let auth_input_index = take_u16_le(payload, &mut cursor).ok_or_else(|| "truncated CAT auth_input_index".to_string())?;
    let nonce = take_u64_le(payload, &mut cursor).ok_or_else(|| "truncated CAT nonce".to_string())?;
    if nonce == 0 {
        return Err("nonce must be >= 1".to_string());
    }

    let op = match op {
        0 => {
            let token_version = take_u8(payload, &mut cursor).ok_or_else(|| "truncated CAT token version".to_string())?;
            validate_token_version(token_version)?;

            let decimals = take_u8(payload, &mut cursor).ok_or_else(|| "truncated CAT decimals".to_string())?;
            if decimals > CAT_MAX_DECIMALS {
                return Err(format!("decimals `{decimals}` above max `{CAT_MAX_DECIMALS}`"));
            }

            let raw_supply_mode = take_u8(payload, &mut cursor).ok_or_else(|| "truncated CAT supply mode".to_string())?;
            let supply_mode = match raw_supply_mode {
                0 => AtomicPayloadSupplyMode::Uncapped,
                1 => AtomicPayloadSupplyMode::Capped,
                _ => return Err(format!("invalid supply mode `{raw_supply_mode}`")),
            };

            let max_supply = take_u128_le(payload, &mut cursor).ok_or_else(|| "truncated CAT max_supply".to_string())?;
            let mint_authority_owner_id = take_32(payload, &mut cursor).ok_or_else(|| "truncated CAT mint authority".to_string())?;
            let name_len = take_u8(payload, &mut cursor).ok_or_else(|| "truncated CAT name length".to_string())? as usize;
            let symbol_len = take_u8(payload, &mut cursor).ok_or_else(|| "truncated CAT symbol length".to_string())? as usize;
            let metadata_len = take_u16_le(payload, &mut cursor).ok_or_else(|| "truncated CAT metadata length".to_string())? as usize;

            if name_len > CAT_MAX_NAME_LEN || symbol_len > CAT_MAX_SYMBOL_LEN || metadata_len > CAT_MAX_METADATA_LEN {
                return Err("string field exceeds allowed length".to_string());
            }

            let name = take_vec(payload, &mut cursor, name_len).ok_or_else(|| "truncated CAT name".to_string())?;
            let symbol = take_vec(payload, &mut cursor, symbol_len).ok_or_else(|| "truncated CAT symbol".to_string())?;
            let metadata = take_vec(payload, &mut cursor, metadata_len).ok_or_else(|| "truncated CAT metadata".to_string())?;

            if std::str::from_utf8(&name).is_err() || std::str::from_utf8(&symbol).is_err() {
                return Err("name/symbol must be valid utf-8".to_string());
            }

            match supply_mode {
                AtomicPayloadSupplyMode::Capped if max_supply == 0 => {
                    return Err("capped assets require non-zero max_supply".to_string())
                }
                AtomicPayloadSupplyMode::Uncapped if max_supply != 0 => {
                    return Err("uncapped assets must encode max_supply=0".to_string())
                }
                _ => {}
            }

            let platform_tag = parse_optional_platform_tag_tail(payload, &mut cursor)?;

            AtomicPayloadOp::CreateAsset {
                token_version,
                decimals,
                supply_mode,
                max_supply,
                mint_authority_owner_id,
                name,
                symbol,
                metadata,
                platform_tag,
            }
        }
        1 => {
            let asset_id = take_32(payload, &mut cursor).ok_or_else(|| "truncated CAT asset_id".to_string())?;
            let to_owner_id = take_32(payload, &mut cursor).ok_or_else(|| "truncated CAT to_owner_id".to_string())?;
            let amount = take_u128_le(payload, &mut cursor).ok_or_else(|| "truncated CAT transfer amount".to_string())?;
            if amount == 0 {
                return Err("transfer amount must be non-zero".to_string());
            }
            AtomicPayloadOp::Transfer { asset_id, to_owner_id, amount }
        }
        2 => {
            let asset_id = take_32(payload, &mut cursor).ok_or_else(|| "truncated CAT asset_id".to_string())?;
            let to_owner_id = take_32(payload, &mut cursor).ok_or_else(|| "truncated CAT to_owner_id".to_string())?;
            let amount = take_u128_le(payload, &mut cursor).ok_or_else(|| "truncated CAT mint amount".to_string())?;
            if amount == 0 {
                return Err("mint amount must be non-zero".to_string());
            }
            AtomicPayloadOp::Mint { asset_id, to_owner_id, amount }
        }
        3 => {
            let asset_id = take_32(payload, &mut cursor).ok_or_else(|| "truncated CAT asset_id".to_string())?;
            let amount = take_u128_le(payload, &mut cursor).ok_or_else(|| "truncated CAT burn amount".to_string())?;
            if amount == 0 {
                return Err("burn amount must be non-zero".to_string());
            }
            AtomicPayloadOp::Burn { asset_id, amount }
        }
        4 => {
            let (token_version, decimals, supply_mode, max_supply, mint_authority_owner_id, name, symbol, metadata) =
                parse_create_asset_common(payload, &mut cursor)?;
            let initial_mint_amount =
                take_u128_le(payload, &mut cursor).ok_or_else(|| "truncated CAT initial mint amount".to_string())?;
            let initial_mint_to_owner_id =
                take_32(payload, &mut cursor).ok_or_else(|| "truncated CAT initial mint owner id".to_string())?;
            if initial_mint_amount == 0 && initial_mint_to_owner_id != [0u8; 32] {
                return Err("initial_mint_to_owner_id must be zero when initial_mint_amount is zero".to_string());
            }
            if initial_mint_amount > 0 && initial_mint_to_owner_id == [0u8; 32] {
                return Err("initial_mint_to_owner_id must be non-zero when initial_mint_amount is non-zero".to_string());
            }
            let platform_tag = parse_optional_platform_tag_tail(payload, &mut cursor)?;
            AtomicPayloadOp::CreateAssetWithMint {
                token_version,
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
            }
        }
        5 => {
            let token_version = take_u8(payload, &mut cursor).ok_or_else(|| "truncated CAT token version".to_string())?;
            validate_token_version(token_version)?;
            let curve_version = take_u8(payload, &mut cursor).ok_or_else(|| "truncated CAT liquidity curve version".to_string())?;
            validate_liquidity_curve_version(curve_version)?;

            let decimals = take_u8(payload, &mut cursor).ok_or_else(|| "truncated CAT decimals".to_string())?;
            if decimals != CAT_LIQUIDITY_TOKEN_DECIMALS {
                return Err(format!("liquidity asset decimals must be `{CAT_LIQUIDITY_TOKEN_DECIMALS}`"));
            }
            let max_supply = take_u128_le(payload, &mut cursor).ok_or_else(|| "truncated CAT max_supply".to_string())?;
            if !(CAT_MIN_LIQUIDITY_SUPPLY_RAW..=CAT_MAX_LIQUIDITY_SUPPLY_RAW).contains(&max_supply) {
                return Err(format!(
                    "liquidity asset max_supply must be in `{CAT_MIN_LIQUIDITY_SUPPLY_RAW}..={CAT_MAX_LIQUIDITY_SUPPLY_RAW}`"
                ));
            }
            let name_len = take_u8(payload, &mut cursor).ok_or_else(|| "truncated CAT name length".to_string())? as usize;
            let symbol_len = take_u8(payload, &mut cursor).ok_or_else(|| "truncated CAT symbol length".to_string())? as usize;
            let metadata_len = take_u16_le(payload, &mut cursor).ok_or_else(|| "truncated CAT metadata length".to_string())? as usize;
            if name_len > CAT_MAX_NAME_LEN || symbol_len > CAT_MAX_SYMBOL_LEN || metadata_len > CAT_MAX_METADATA_LEN {
                return Err("string field exceeds allowed length".to_string());
            }
            let name = take_vec(payload, &mut cursor, name_len).ok_or_else(|| "truncated CAT name".to_string())?;
            let symbol = take_vec(payload, &mut cursor, symbol_len).ok_or_else(|| "truncated CAT symbol".to_string())?;
            let metadata = take_vec(payload, &mut cursor, metadata_len).ok_or_else(|| "truncated CAT metadata".to_string())?;
            if std::str::from_utf8(&name).is_err() || std::str::from_utf8(&symbol).is_err() {
                return Err("name/symbol must be valid utf-8".to_string());
            }

            let seed_reserve_sompi = take_u64_le(payload, &mut cursor).ok_or_else(|| "truncated CAT seed reserve".to_string())?;
            if seed_reserve_sompi != CAT_MIN_LIQUIDITY_SEED_RESERVE_SOMPI {
                return Err(format!("liquidity asset seed_reserve_sompi must be exactly `{CAT_MIN_LIQUIDITY_SEED_RESERVE_SOMPI}`"));
            }
            let fee_bps = take_u16_le(payload, &mut cursor).ok_or_else(|| "truncated CAT fee bps".to_string())?;
            if !(fee_bps == 0 || (CAT_MIN_LIQUIDITY_FEE_BPS..=CAT_MAX_LIQUIDITY_FEE_BPS).contains(&fee_bps)) {
                return Err(format!(
                    "fee_bps must be 0 or in {}..={}, got `{}`",
                    CAT_MIN_LIQUIDITY_FEE_BPS, CAT_MAX_LIQUIDITY_FEE_BPS, fee_bps
                ));
            }
            let recipient_count = take_u8(payload, &mut cursor).ok_or_else(|| "truncated CAT recipient count".to_string())? as usize;
            if recipient_count > CAT_MAX_LIQUIDITY_RECIPIENTS {
                return Err(format!("recipient_count above max `{CAT_MAX_LIQUIDITY_RECIPIENTS}`"));
            }
            if fee_bps == 0 && recipient_count != 0 {
                return Err("recipient_count must be 0 when fee_bps is 0".to_string());
            }
            if fee_bps > 0 && !(1..=CAT_MAX_LIQUIDITY_RECIPIENTS).contains(&recipient_count) {
                return Err("recipient_count must be 1 or 2 when fee_bps > 0".to_string());
            }
            let mut recipients = Vec::with_capacity(recipient_count);
            for _ in 0..recipient_count {
                recipients.push(parse_recipient_address(payload, &mut cursor)?);
            }
            if recipients.len() == 2 {
                if recipients[0] == recipients[1] {
                    return Err("duplicate liquidity recipients are not allowed".to_string());
                }
                if recipient_order_key(&recipients[0]) > recipient_order_key(&recipients[1]) {
                    return Err("liquidity recipients must be canonically sorted".to_string());
                }
            }

            let launch_buy_sompi = take_u64_le(payload, &mut cursor).ok_or_else(|| "truncated CAT launch buy sompi".to_string())?;
            let launch_buy_min_token_out =
                take_u128_le(payload, &mut cursor).ok_or_else(|| "truncated CAT launch buy min token out".to_string())?;
            if launch_buy_sompi == 0 && launch_buy_min_token_out != 0 {
                return Err("launch_buy_min_token_out must be 0 when launch_buy_sompi is 0".to_string());
            }
            if launch_buy_sompi > 0 && launch_buy_min_token_out == 0 {
                return Err("launch_buy_min_token_out must be >0 when launch_buy_sompi is >0".to_string());
            }
            let (platform_tag, liquidity_unlock_target_sompi) = parse_optional_liquidity_create_tail(payload, &mut cursor)?;

            AtomicPayloadOp::CreateLiquidityAsset {
                token_version,
                curve_version,
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
            }
        }
        6 => {
            let asset_id = take_32(payload, &mut cursor).ok_or_else(|| "truncated CAT asset_id".to_string())?;
            let expected_pool_nonce =
                take_u64_le(payload, &mut cursor).ok_or_else(|| "truncated CAT expected_pool_nonce".to_string())?;
            if expected_pool_nonce == 0 {
                return Err("buy expected_pool_nonce must be >= 1".to_string());
            }
            let cpay_in_sompi = take_u64_le(payload, &mut cursor).ok_or_else(|| "truncated CAT cpay in".to_string())?;
            let min_token_out = take_u128_le(payload, &mut cursor).ok_or_else(|| "truncated CAT min token out".to_string())?;
            if cpay_in_sompi == 0 {
                return Err("buy cpay_in_sompi must be >0".to_string());
            }
            if min_token_out == 0 {
                return Err("buy min_token_out must be >0".to_string());
            }
            AtomicPayloadOp::BuyLiquidityExactIn { asset_id, expected_pool_nonce, cpay_in_sompi, min_token_out }
        }
        7 => {
            let asset_id = take_32(payload, &mut cursor).ok_or_else(|| "truncated CAT asset_id".to_string())?;
            let expected_pool_nonce =
                take_u64_le(payload, &mut cursor).ok_or_else(|| "truncated CAT expected_pool_nonce".to_string())?;
            if expected_pool_nonce == 0 {
                return Err("sell expected_pool_nonce must be >= 1".to_string());
            }
            let token_in = take_u128_le(payload, &mut cursor).ok_or_else(|| "truncated CAT token_in".to_string())?;
            let min_cpay_out_sompi = take_u64_le(payload, &mut cursor).ok_or_else(|| "truncated CAT min cpay out".to_string())?;
            let cpay_receive_output_index =
                take_u16_le(payload, &mut cursor).ok_or_else(|| "truncated CAT cpay receive output index".to_string())?;
            if token_in == 0 {
                return Err("sell token_in must be >0".to_string());
            }
            if min_cpay_out_sompi == 0 {
                return Err("sell min_cpay_out_sompi must be >0".to_string());
            }
            AtomicPayloadOp::SellLiquidityExactIn {
                asset_id,
                expected_pool_nonce,
                token_in,
                min_cpay_out_sompi,
                cpay_receive_output_index,
            }
        }
        8 => {
            let asset_id = take_32(payload, &mut cursor).ok_or_else(|| "truncated CAT asset_id".to_string())?;
            let expected_pool_nonce =
                take_u64_le(payload, &mut cursor).ok_or_else(|| "truncated CAT expected_pool_nonce".to_string())?;
            if expected_pool_nonce == 0 {
                return Err("claim expected_pool_nonce must be >= 1".to_string());
            }
            let recipient_index = take_u8(payload, &mut cursor).ok_or_else(|| "truncated CAT claim recipient index".to_string())?;
            let claim_amount_sompi = take_u64_le(payload, &mut cursor).ok_or_else(|| "truncated CAT claim amount".to_string())?;
            let claim_receive_output_index =
                take_u16_le(payload, &mut cursor).ok_or_else(|| "truncated CAT claim receive output index".to_string())?;
            if claim_amount_sompi == 0 {
                return Err("claim amount must be >0".to_string());
            }
            AtomicPayloadOp::ClaimLiquidityFees {
                asset_id,
                expected_pool_nonce,
                recipient_index,
                claim_amount_sompi,
                claim_receive_output_index,
            }
        }
        _ => unreachable!(),
    };

    if cursor != payload.len() {
        return Err("unexpected trailing bytes".to_string());
    }

    Ok(Some(ParsedAtomicPayload { auth_input_index, nonce, op }))
}

fn parse_create_asset_common(
    payload: &[u8],
    cursor: &mut usize,
) -> Result<(u8, u8, AtomicPayloadSupplyMode, u128, [u8; 32], Vec<u8>, Vec<u8>, Vec<u8>), String> {
    let token_version = take_u8(payload, cursor).ok_or_else(|| "truncated CAT token version".to_string())?;
    validate_token_version(token_version)?;

    let decimals = take_u8(payload, cursor).ok_or_else(|| "truncated CAT decimals".to_string())?;
    if decimals > CAT_MAX_DECIMALS {
        return Err(format!("decimals `{decimals}` above max `{CAT_MAX_DECIMALS}`"));
    }
    let raw_supply_mode = take_u8(payload, cursor).ok_or_else(|| "truncated CAT supply mode".to_string())?;
    let supply_mode = match raw_supply_mode {
        0 => AtomicPayloadSupplyMode::Uncapped,
        1 => AtomicPayloadSupplyMode::Capped,
        _ => return Err(format!("invalid supply mode `{raw_supply_mode}`")),
    };
    let max_supply = take_u128_le(payload, cursor).ok_or_else(|| "truncated CAT max_supply".to_string())?;
    let mint_authority_owner_id = take_32(payload, cursor).ok_or_else(|| "truncated CAT mint authority".to_string())?;
    let name_len = take_u8(payload, cursor).ok_or_else(|| "truncated CAT name length".to_string())? as usize;
    let symbol_len = take_u8(payload, cursor).ok_or_else(|| "truncated CAT symbol length".to_string())? as usize;
    let metadata_len = take_u16_le(payload, cursor).ok_or_else(|| "truncated CAT metadata length".to_string())? as usize;
    if name_len > CAT_MAX_NAME_LEN || symbol_len > CAT_MAX_SYMBOL_LEN || metadata_len > CAT_MAX_METADATA_LEN {
        return Err("string field exceeds allowed length".to_string());
    }
    let name = take_vec(payload, cursor, name_len).ok_or_else(|| "truncated CAT name".to_string())?;
    let symbol = take_vec(payload, cursor, symbol_len).ok_or_else(|| "truncated CAT symbol".to_string())?;
    let metadata = take_vec(payload, cursor, metadata_len).ok_or_else(|| "truncated CAT metadata".to_string())?;
    if std::str::from_utf8(&name).is_err() || std::str::from_utf8(&symbol).is_err() {
        return Err("name/symbol must be valid utf-8".to_string());
    }
    match supply_mode {
        AtomicPayloadSupplyMode::Capped if max_supply == 0 => return Err("capped assets require non-zero max_supply".to_string()),
        AtomicPayloadSupplyMode::Uncapped if max_supply != 0 => return Err("uncapped assets must encode max_supply=0".to_string()),
        _ => {}
    }
    Ok((token_version, decimals, supply_mode, max_supply, mint_authority_owner_id, name, symbol, metadata))
}

fn validate_token_version(version: u8) -> Result<(), String> {
    if (1..=CAT_MAX_TOKEN_VERSION).contains(&version) && version == CAT_CURRENT_TOKEN_VERSION {
        Ok(())
    } else {
        Err(format!("unsupported CAT token version `{version}`"))
    }
}

fn validate_liquidity_curve_version(version: u8) -> Result<(), String> {
    if (1..=CAT_MAX_LIQUIDITY_CURVE_VERSION).contains(&version) && version == CAT_CURRENT_LIQUIDITY_CURVE_VERSION {
        Ok(())
    } else {
        Err(format!("unsupported CAT liquidity curve version `{version}`"))
    }
}

fn parse_optional_platform_tag_tail(payload: &[u8], cursor: &mut usize) -> Result<Vec<u8>, String> {
    if *cursor == payload.len() {
        return Ok(Vec::new());
    }
    parse_platform_tag(payload, cursor)
}

fn parse_optional_liquidity_create_tail(payload: &[u8], cursor: &mut usize) -> Result<(Vec<u8>, u64), String> {
    if *cursor == payload.len() {
        return Ok((Vec::new(), 0));
    }
    let platform_tag = parse_platform_tag(payload, cursor)?;
    let liquidity_unlock_target_sompi =
        take_u64_le(payload, cursor).ok_or_else(|| "truncated CAT liquidity unlock target".to_string())?;
    if liquidity_unlock_target_sompi > MAX_SOMPI {
        return Err(format!("liquidity unlock target exceeds MAX_SOMPI `{MAX_SOMPI}`"));
    }
    Ok((platform_tag, liquidity_unlock_target_sompi))
}

fn parse_platform_tag(payload: &[u8], cursor: &mut usize) -> Result<Vec<u8>, String> {
    let platform_tag_len = take_u8(payload, cursor).ok_or_else(|| "truncated CAT platform tag length".to_string())? as usize;
    if platform_tag_len > CAT_MAX_PLATFORM_TAG_LEN {
        return Err(format!("platform_tag exceeds max `{CAT_MAX_PLATFORM_TAG_LEN}` bytes"));
    }
    let platform_tag = take_vec(payload, cursor, platform_tag_len).ok_or_else(|| "truncated CAT platform tag".to_string())?;
    if std::str::from_utf8(&platform_tag).is_err() {
        return Err("platform_tag must be valid utf-8".to_string());
    }
    Ok(platform_tag)
}

fn parse_recipient_address(payload: &[u8], cursor: &mut usize) -> Result<AtomicPayloadRecipientAddress, String> {
    let address_version = take_u8(payload, cursor).ok_or_else(|| "truncated CAT recipient address version".to_string())?;
    let expected_len = match address_version {
        0 => 32usize,
        1 => 33usize,
        8 => 32usize,
        _ => return Err(format!("unsupported recipient address_version `{address_version}`")),
    };
    let address_payload =
        take_vec(payload, cursor, expected_len).ok_or_else(|| "truncated CAT recipient address payload".to_string())?;
    Ok(AtomicPayloadRecipientAddress { address_version, address_payload })
}

fn recipient_order_key(recipient: &AtomicPayloadRecipientAddress) -> (u8, &[u8]) {
    (recipient.address_version, recipient.address_payload.as_slice())
}

pub(crate) fn atomic_owner_id_from_script(script_public_key: &ScriptPublicKey) -> Option<[u8; 32]> {
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

pub(crate) fn atomic_owner_id_from_address_components(address_version: u8, address_payload: &[u8]) -> Option<[u8; 32]> {
    let auth_scheme = match address_version {
        0 if address_payload.len() == 32 => OWNER_AUTH_SCHEME_PUBKEY,
        1 if address_payload.len() == 33 => OWNER_AUTH_SCHEME_PUBKEY_ECDSA,
        8 if address_payload.len() == 32 => OWNER_AUTH_SCHEME_SCRIPT_HASH,
        _ => return None,
    };
    let pubkey_len = u16::try_from(address_payload.len()).ok()?;
    let mut hasher = Blake2bParams::new().hash_length(32).to_state();
    hasher.update(CAT_OWNER_DOMAIN);
    hasher.update(&[auth_scheme]);
    hasher.update(&pubkey_len.to_le_bytes());
    hasher.update(address_payload);
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

fn take_bytes<'a>(payload: &'a [u8], cursor: &mut usize, len: usize) -> Option<&'a [u8]> {
    if *cursor + len > payload.len() {
        return None;
    }
    let out = &payload[*cursor..*cursor + len];
    *cursor += len;
    Some(out)
}

fn take_u8(payload: &[u8], cursor: &mut usize) -> Option<u8> {
    let out = *payload.get(*cursor)?;
    *cursor += 1;
    Some(out)
}

fn take_u16_le(payload: &[u8], cursor: &mut usize) -> Option<u16> {
    let bytes = take_bytes(payload, cursor, 2)?;
    Some(u16::from_le_bytes(bytes.try_into().ok()?))
}

fn take_u64_le(payload: &[u8], cursor: &mut usize) -> Option<u64> {
    let bytes = take_bytes(payload, cursor, 8)?;
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

fn take_u128_le(payload: &[u8], cursor: &mut usize) -> Option<u128> {
    let bytes = take_bytes(payload, cursor, 16)?;
    Some(u128::from_le_bytes(bytes.try_into().ok()?))
}

fn take_32(payload: &[u8], cursor: &mut usize) -> Option<[u8; 32]> {
    let bytes = take_bytes(payload, cursor, 32)?;
    Some(bytes.try_into().ok()?)
}

fn take_vec(payload: &[u8], cursor: &mut usize, len: usize) -> Option<Vec<u8>> {
    Some(take_bytes(payload, cursor, len)?.to_vec())
}

#[cfg(test)]
mod tests {
    use super::super::errors::TxRuleError;
    use super::TxValidationFlags;
    use core::str::FromStr;
    use cryptix_consensus_core::subnets::SubnetworkId;
    use cryptix_consensus_core::tx::{MutableTransaction, PopulatedTransaction, ScriptVec, TransactionId, UtxoEntry};
    use cryptix_consensus_core::tx::{ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput};
    use cryptix_consensus_core::{mass::MassCalculator, sign::sign};
    use cryptix_txscript::caches::TxScriptCacheCounters;
    use cryptix_txscript_errors::TxScriptError;
    use itertools::Itertools;
    use secp256k1::Secp256k1;
    use smallvec::SmallVec;
    use std::iter::once;
    use std::sync::Arc;

    use crate::{params::MAINNET_PARAMS, processes::transaction_validator::TransactionValidator};

    #[test]
    fn atomic_owner_id_accepts_standard_p2sh_script() {
        let script_public_key = cryptix_txscript::pay_to_script_hash_script(&[0x51]);

        assert_eq!(script_public_key.script().len(), 35);
        assert!(super::atomic_owner_id_from_script(&script_public_key).is_some());
    }

    #[test]
    fn check_signature_test() {
        let mut params = MAINNET_PARAMS.clone();
        params.max_tx_inputs = 10;
        params.max_tx_outputs = 15;
        let tv = TransactionValidator::new_for_tests(
            params.max_tx_inputs,
            params.max_tx_outputs,
            params.max_signature_script_len,
            params.max_script_public_key_len,
            params.ghostdag_k,
            params.coinbase_payload_script_public_key_max_len,
            params.coinbase_maturity,
            Default::default(),
        );

        let prev_tx_id = TransactionId::from_str("746915c8dfc5e1550eacbe1d87625a105750cf1a65aaddd1baa60f8bcf7e953c").unwrap();

        let mut bytes = [0u8; 66];
        faster_hex::hex_decode("4176cf2ee56b3eed1e8da083851f41cae11532fc70a63ca1ca9f17bc9a4c2fd3dcdf60df1c1a57465f0d112995a6f289511c8e0a79c806fb79165544a439d11c0201".as_bytes(), &mut bytes).unwrap();
        let signature_script = bytes.to_vec();

        let mut bytes = [0u8; 34];
        faster_hex::hex_decode("20e1d5835e09f3c3dad209debcb7b3bf3fb0e0d9642471f5db36c9ea58338b06beac".as_bytes(), &mut bytes).unwrap();
        let script_pub_key_1 = SmallVec::from(bytes.to_vec());

        let mut bytes = [0u8; 34];
        faster_hex::hex_decode("200749c89953b463d1e186a16a941f9354fa3fff313c391149e47961b95dd4df28ac".as_bytes(), &mut bytes).unwrap();
        let script_pub_key_2 = SmallVec::from(bytes.to_vec());

        let tx = Transaction::new(
            0,
            vec![TransactionInput {
                previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id, index: 1 },
                signature_script,
                sequence: 0,
                sig_op_count: 1,
            }],
            vec![
                TransactionOutput { value: 10360487799, script_public_key: ScriptPublicKey::new(0, script_pub_key_2) },
                TransactionOutput { value: 10518958752, script_public_key: ScriptPublicKey::new(0, script_pub_key_1.clone()) },
            ],
            0,
            SubnetworkId::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            0,
            vec![],
        );

        let populated_tx = PopulatedTransaction::new(
            &tx,
            vec![UtxoEntry {
                amount: 20879456551,
                script_public_key: ScriptPublicKey::new(0, script_pub_key_1),
                block_daa_score: 32022768,
                is_coinbase: false,
            }],
        );

        tv.check_scripts(&populated_tx).expect("Signature check failed");
    }

    #[test]
    fn check_incorrect_signature_test() {
        let mut params = MAINNET_PARAMS.clone();
        params.max_tx_inputs = 10;
        params.max_tx_outputs = 15;
        let tv = TransactionValidator::new_for_tests(
            params.max_tx_inputs,
            params.max_tx_outputs,
            params.max_signature_script_len,
            params.max_script_public_key_len,
            params.ghostdag_k,
            params.coinbase_payload_script_public_key_max_len,
            params.coinbase_maturity,
            Default::default(),
        );

        // Taken from: 3f582463d73c77d93f278b7bf649bd890e75fe9bb8a1edd7a6854df1a2a2bfc1
        let prev_tx_id = TransactionId::from_str("746915c8dfc5e1550eacbe1d87625a105750cf1a65aaddd1baa60f8bcf7e953c").unwrap();

        let mut bytes = [0u8; 66];
        faster_hex::hex_decode("4176cf2ee56b3eed1e8da083851f41cae11532fc70a63ca1ca9f17bc9a4c2fd3dcdf60df1c1a57465f0d112995a6f289511c8e0a79c806fb79165544a439d11c0201".as_bytes(), &mut bytes).unwrap();
        let signature_script = bytes.to_vec();

        let mut bytes = [0u8; 34];
        faster_hex::hex_decode("20e1d5835e09f3c3dad209debcb7b3bf3fb0e0d9642471f5db36c9ea58338b06beac".as_bytes(), &mut bytes).unwrap();
        let script_pub_key_1 = SmallVec::from(bytes.to_vec());

        let mut bytes = [0u8; 34];
        faster_hex::hex_decode("200749c89953b463d1e186a16a941f9354fa3fff313c391149e47961b95dd4df28ac".as_bytes(), &mut bytes).unwrap();
        let script_pub_key_2 = SmallVec::from(bytes.to_vec());

        let tx = Transaction::new(
            0,
            vec![TransactionInput {
                previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id, index: 1 },
                signature_script,
                sequence: 0,
                sig_op_count: 1,
            }],
            vec![
                TransactionOutput { value: 10360487799, script_public_key: ScriptPublicKey::new(0, script_pub_key_2.clone()) },
                TransactionOutput { value: 10518958752, script_public_key: ScriptPublicKey::new(0, script_pub_key_1) },
            ],
            0,
            SubnetworkId::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            0,
            vec![],
        );

        let populated_tx = PopulatedTransaction::new(
            &tx,
            vec![UtxoEntry {
                amount: 20879456551,
                script_public_key: ScriptPublicKey::new(0, script_pub_key_2),
                block_daa_score: 32022768,
                is_coinbase: false,
            }],
        );

        assert!(tv.check_scripts(&populated_tx).is_err(), "Failing Signature Test Failed");
    }

    #[test]
    fn check_multi_signature_test() {
        let mut params = MAINNET_PARAMS.clone();
        params.max_tx_inputs = 10;
        params.max_tx_outputs = 15;
        let tv = TransactionValidator::new_for_tests(
            params.max_tx_inputs,
            params.max_tx_outputs,
            params.max_signature_script_len,
            params.max_script_public_key_len,
            params.ghostdag_k,
            params.coinbase_payload_script_public_key_max_len,
            params.coinbase_maturity,
            Default::default(),
        );

        // Taken from: d839d29b549469d0f9a23e51febe68d4084967a6a477868b511a5a8d88c5ae06
        let prev_tx_id = TransactionId::from_str("63020db736215f8b1105a9281f7bcbb6473d965ecc45bb2fb5da59bd35e6ff84").unwrap();

        let mut bytes = [0u8; 269];
        faster_hex::hex_decode("41ca6f8d104b47ca8ab133d98b3794b49f00ec5d2dce8253e78de035dfbc8f40a2fefa3086c3a181d9f1755a8f4ada4f8a4b8982b361853c8020009e1a752debce0141fdb58c2c25fcfe37d427967c34700f92e9eb1df0f2f9ff366444d92357ff35a270ee5445287031e4c0f72acda20876ccf918de1039a41e9b5f83b3737223f995014c875220ecdd9ec9f2c53ed8e5a170cc88354e133299022da55e1e8bd3c61d8b9dcbd7df2068f191b6aca3d9d8cfa2edb0c44a10fc87dc36b62e1d02228257ccdf979b1fce20b1503ef14aa6773ba3a1f012dbea2992e181766c35c5bc17465b5f57807540bf2006e161ced6b77c11b9a317080a899121a9c6df30a76490402f9a3b7e18bce97b54ae".as_bytes(), &mut bytes).unwrap();
        let signature_script = bytes.to_vec();

        let mut bytes = [0u8; 35];
        faster_hex::hex_decode("aa2071b6c2c604a8830a1484ba469e845c37bb0af32f044bc8fd0c892c8878419e8587".as_bytes(), &mut bytes)
            .unwrap();
        let script_pub_key_1 = SmallVec::from(bytes.to_vec());

        let mut bytes = [0u8; 34];
        faster_hex::hex_decode("206c376f9da440494e18b283803698ed13249af93be3e99f58f42d7d82744d3d15ac".as_bytes(), &mut bytes).unwrap();
        let script_pub_key_2 = SmallVec::from(bytes.to_vec());

        let tx = Transaction::new(
            0,
            vec![TransactionInput {
                previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id, index: 0 },
                signature_script,
                sequence: 0,
                sig_op_count: 4,
            }],
            vec![
                TransactionOutput { value: 10000000000000, script_public_key: ScriptPublicKey::new(0, script_pub_key_2) },
                TransactionOutput { value: 2792999990000, script_public_key: ScriptPublicKey::new(0, script_pub_key_1.clone()) },
            ],
            0,
            SubnetworkId::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            0,
            vec![],
        );

        let populated_tx = PopulatedTransaction::new(
            &tx,
            vec![UtxoEntry {
                amount: 12793000000000,
                script_public_key: ScriptPublicKey::new(0, script_pub_key_1),
                block_daa_score: 36151168,
                is_coinbase: false,
            }],
        );
        tv.check_scripts(&populated_tx).expect("Signature check failed");
    }

    #[test]
    fn check_last_sig_incorrect_multi_signature_test() {
        let mut params = MAINNET_PARAMS.clone();
        params.max_tx_inputs = 10;
        params.max_tx_outputs = 15;
        let tv = TransactionValidator::new_for_tests(
            params.max_tx_inputs,
            params.max_tx_outputs,
            params.max_signature_script_len,
            params.max_script_public_key_len,
            params.ghostdag_k,
            params.coinbase_payload_script_public_key_max_len,
            params.coinbase_maturity,
            Default::default(),
        );

        // Taken from: d839d29b549469d0f9a23e51febe68d4084967a6a477868b511a5a8d88c5ae06
        let prev_tx_id = TransactionId::from_str("63020db736215f8b1105a9281f7bcbb6473d965ecc45bb2fb5da59bd35e6ff84").unwrap();

        let mut bytes = [0u8; 269];
        faster_hex::hex_decode("41ca6f8d104b47ca8ab133d98b3794b49f00ec5d2dce8253e78de035dfbc8f40a2fefa3086c3a181d9f1755a8f4ada4f8a4b8982b361853c8020009e1a752debce0141fdb58c2c25fcfe37d427967c34700f92e9eb1df0f2f9ff366444d92357ff3da270ee5445287031e4c0f72acda20876ccf918de1039a41e9b5f83b3737223f995014c875220ecdd9ec9f2c53ed8e5a170cc88354e133299022da55e1e8bd3c61d8b9dcbd7df2068f191b6aca3d9d8cfa2edb0c44a10fc87dc36b62e1d02228257ccdf979b1fce20b1503ef14aa6773ba3a1f012dbea2992e181766c35c5bc17465b5f57807540bf2006e161ced6b77c11b9a317080a899121a9c6df30a76490402f9a3b7e18bce97b54ae".as_bytes(), &mut bytes).unwrap();
        let signature_script = bytes.to_vec();

        let mut bytes = [0u8; 35];
        faster_hex::hex_decode("aa2071b6c2c604a8830a1484ba469e845c37bb0af32f044bc8fd0c892c8878419e8587".as_bytes(), &mut bytes)
            .unwrap();
        let script_pub_key_1 = SmallVec::from(bytes.to_vec());

        let mut bytes = [0u8; 34];
        faster_hex::hex_decode("206c376f9da440494e18b283803698ed13249af93be3e99f58f42d7d82744d3d15ac".as_bytes(), &mut bytes).unwrap();
        let script_pub_key_2 = SmallVec::from(bytes.to_vec());

        let tx = Transaction::new(
            0,
            vec![TransactionInput {
                previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id, index: 0 },
                signature_script,
                sequence: 0,
                sig_op_count: 4,
            }],
            vec![
                TransactionOutput { value: 10000000000000, script_public_key: ScriptPublicKey::new(0, script_pub_key_2) },
                TransactionOutput { value: 2792999990000, script_public_key: ScriptPublicKey::new(0, script_pub_key_1.clone()) },
            ],
            0,
            SubnetworkId::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            0,
            vec![],
        );

        let populated_tx = PopulatedTransaction::new(
            &tx,
            vec![UtxoEntry {
                amount: 12793000000000,
                script_public_key: ScriptPublicKey::new(0, script_pub_key_1),
                block_daa_score: 36151168,
                is_coinbase: false,
            }],
        );

        assert!(tv.check_scripts(&populated_tx) == Err(TxRuleError::SignatureInvalid(TxScriptError::NullFail)));
    }

    #[test]
    fn check_first_sig_incorrect_multi_signature_test() {
        let mut params = MAINNET_PARAMS.clone();
        params.max_tx_inputs = 10;
        params.max_tx_outputs = 15;
        let tv = TransactionValidator::new_for_tests(
            params.max_tx_inputs,
            params.max_tx_outputs,
            params.max_signature_script_len,
            params.max_script_public_key_len,
            params.ghostdag_k,
            params.coinbase_payload_script_public_key_max_len,
            params.coinbase_maturity,
            Default::default(),
        );

        // Taken from: d839d29b549469d0f9a23e51febe68d4084967a6a477868b511a5a8d88c5ae06
        let prev_tx_id = TransactionId::from_str("63020db736215f8b1105a9281f7bcbb6473d965ecc45bb2fb5da59bd35e6ff84").unwrap();

        let mut bytes = [0u8; 269];
        faster_hex::hex_decode("41ca6f8d104b47ca8ab133d98b3794b49f00ec5d2dce8253e78de035dfbc8f41a2fefa3086c3a181d9f1755a8f4ada4f8a4b8982b361853c8020009e1a752debce0141fdb58c2c25fcfe37d427967c34700f92e9eb1df0f2f9ff366444d92357ff35a270ee5445287031e4c0f72acda20876ccf918de1039a41e9b5f83b3737223f995014c875220ecdd9ec9f2c53ed8e5a170cc88354e133299022da55e1e8bd3c61d8b9dcbd7df2068f191b6aca3d9d8cfa2edb0c44a10fc87dc36b62e1d02228257ccdf979b1fce20b1503ef14aa6773ba3a1f012dbea2992e181766c35c5bc17465b5f57807540bf2006e161ced6b77c11b9a317080a899121a9c6df30a76490402f9a3b7e18bce97b54ae".as_bytes(), &mut bytes).unwrap();
        let signature_script = bytes.to_vec();

        let mut bytes = [0u8; 35];
        faster_hex::hex_decode("aa2071b6c2c604a8830a1484ba469e845c37bb0af32f044bc8fd0c892c8878419e8587".as_bytes(), &mut bytes)
            .unwrap();
        let script_pub_key_1 = SmallVec::from(bytes.to_vec());

        let mut bytes = [0u8; 34];
        faster_hex::hex_decode("206c376f9da440494e18b283803698ed13249af93be3e99f58f42d7d82744d3d15ac".as_bytes(), &mut bytes).unwrap();
        let script_pub_key_2 = SmallVec::from(bytes.to_vec());

        let tx = Transaction::new(
            0,
            vec![TransactionInput {
                previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id, index: 0 },
                signature_script,
                sequence: 0,
                sig_op_count: 4,
            }],
            vec![
                TransactionOutput { value: 10000000000000, script_public_key: ScriptPublicKey::new(0, script_pub_key_2) },
                TransactionOutput { value: 2792999990000, script_public_key: ScriptPublicKey::new(0, script_pub_key_1.clone()) },
            ],
            0,
            SubnetworkId::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            0,
            vec![],
        );

        let populated_tx = PopulatedTransaction::new(
            &tx,
            vec![UtxoEntry {
                amount: 12793000000000,
                script_public_key: ScriptPublicKey::new(0, script_pub_key_1),
                block_daa_score: 36151168,
                is_coinbase: false,
            }],
        );

        assert!(tv.check_scripts(&populated_tx) == Err(TxRuleError::SignatureInvalid(TxScriptError::NullFail)));
    }

    #[test]
    fn check_empty_incorrect_multi_signature_test() {
        let mut params = MAINNET_PARAMS.clone();
        params.max_tx_inputs = 10;
        params.max_tx_outputs = 15;
        let tv = TransactionValidator::new_for_tests(
            params.max_tx_inputs,
            params.max_tx_outputs,
            params.max_signature_script_len,
            params.max_script_public_key_len,
            params.ghostdag_k,
            params.coinbase_payload_script_public_key_max_len,
            params.coinbase_maturity,
            Default::default(),
        );

        // Taken from: d839d29b549469d0f9a23e51febe68d4084967a6a477868b511a5a8d88c5ae06
        let prev_tx_id = TransactionId::from_str("63020db736215f8b1105a9281f7bcbb6473d965ecc45bb2fb5da59bd35e6ff84").unwrap();

        let mut bytes = [0u8; 139];
        faster_hex::hex_decode("00004c875220ecdd9ec9f2c53ed8e5a170cc88354e133299022da55e1e8bd3c61d8b9dcbd7df2068f191b6aca3d9d8cfa2edb0c44a10fc87dc36b62e1d02228257ccdf979b1fce20b1503ef14aa6773ba3a1f012dbea2992e181766c35c5bc17465b5f57807540bf2006e161ced6b77c11b9a317080a899121a9c6df30a76490402f9a3b7e18bce97b54ae".as_bytes(), &mut bytes).unwrap();
        let signature_script = bytes.to_vec();

        let mut bytes = [0u8; 35];
        faster_hex::hex_decode("aa2071b6c2c604a8830a1484ba469e845c37bb0af32f044bc8fd0c892c8878419e8587".as_bytes(), &mut bytes)
            .unwrap();
        let script_pub_key_1 = SmallVec::from(bytes.to_vec());

        let mut bytes = [0u8; 34];
        faster_hex::hex_decode("206c376f9da440494e18b283803698ed13249af93be3e99f58f42d7d82744d3d15ac".as_bytes(), &mut bytes).unwrap();
        let script_pub_key_2 = SmallVec::from(bytes.to_vec());

        let tx = Transaction::new(
            0,
            vec![TransactionInput {
                previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id, index: 0 },
                signature_script,
                sequence: 0,
                sig_op_count: 4,
            }],
            vec![
                TransactionOutput { value: 10000000000000, script_public_key: ScriptPublicKey::new(0, script_pub_key_2) },
                TransactionOutput { value: 2792999990000, script_public_key: ScriptPublicKey::new(0, script_pub_key_1.clone()) },
            ],
            0,
            SubnetworkId::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            0,
            vec![],
        );

        let populated_tx = PopulatedTransaction::new(
            &tx,
            vec![UtxoEntry {
                amount: 12793000000000,
                script_public_key: ScriptPublicKey::new(0, script_pub_key_1),
                block_daa_score: 36151168,
                is_coinbase: false,
            }],
        );

        let result = tv.check_scripts(&populated_tx);
        assert!(result == Err(TxRuleError::SignatureInvalid(TxScriptError::EvalFalse)));
    }

    #[test]
    fn check_non_push_only_script_sig_test() {
        // We test a situation where the script itself is valid, but the script signature is not push only
        let params = MAINNET_PARAMS.clone();
        let tv = TransactionValidator::new_for_tests(
            params.max_tx_inputs,
            params.max_tx_outputs,
            params.max_signature_script_len,
            params.max_script_public_key_len,
            params.ghostdag_k,
            params.coinbase_payload_script_public_key_max_len,
            params.coinbase_maturity,
            Default::default(),
        );

        let prev_tx_id = TransactionId::from_str("1111111111111111111111111111111111111111111111111111111111111111").unwrap();

        let mut bytes = [0u8; 2];
        faster_hex::hex_decode("5175".as_bytes(), &mut bytes).unwrap(); // OP_TRUE OP_DROP
        let signature_script = bytes.to_vec();

        let mut bytes = [0u8; 1];
        faster_hex::hex_decode("51".as_bytes(), &mut bytes) // OP_TRUE
            .unwrap();
        let script_pub_key_1 = SmallVec::from(bytes.to_vec());

        let tx = Transaction::new(
            0,
            vec![TransactionInput {
                previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id, index: 0 },
                signature_script,
                sequence: 0,
                sig_op_count: 4,
            }],
            vec![TransactionOutput { value: 2792999990000, script_public_key: ScriptPublicKey::new(0, script_pub_key_1.clone()) }],
            0,
            SubnetworkId::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            0,
            vec![],
        );

        let populated_tx = PopulatedTransaction::new(
            &tx,
            vec![UtxoEntry {
                amount: 12793000000000,
                script_public_key: ScriptPublicKey::new(0, script_pub_key_1),
                block_daa_score: 36151168,
                is_coinbase: false,
            }],
        );

        let result = tv.check_scripts(&populated_tx);
        assert!(result == Err(TxRuleError::SignatureInvalid(TxScriptError::SignatureScriptNotPushOnly)));
    }

    #[test]
    fn test_sign() {
        let params = MAINNET_PARAMS.clone();
        let tv = TransactionValidator::new_for_tests(
            params.max_tx_inputs,
            params.max_tx_outputs,
            params.max_signature_script_len,
            params.max_script_public_key_len,
            params.ghostdag_k,
            params.coinbase_payload_script_public_key_max_len,
            params.coinbase_maturity,
            Default::default(),
        );

        let secp = Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());
        let (public_key, _) = public_key.x_only_public_key();
        let script_pub_key = once(0x20).chain(public_key.serialize()).chain(once(0xac)).collect_vec();
        let script_pub_key = ScriptVec::from_slice(&script_pub_key);

        let prev_tx_id = TransactionId::from_str("880eb9819a31821d9d2399e2f35e2433b72637e393d71ecc9b8d0250f49153c3").unwrap();
        let unsigned_tx = Transaction::new(
            0,
            vec![
                TransactionInput {
                    previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id, index: 0 },
                    signature_script: vec![],
                    sequence: 0,
                    sig_op_count: 0,
                },
                TransactionInput {
                    previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id, index: 1 },
                    signature_script: vec![],
                    sequence: 1,
                    sig_op_count: 0,
                },
                TransactionInput {
                    previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id, index: 2 },
                    signature_script: vec![],
                    sequence: 2,
                    sig_op_count: 0,
                },
            ],
            vec![
                TransactionOutput { value: 300, script_public_key: ScriptPublicKey::new(0, script_pub_key.clone()) },
                TransactionOutput { value: 300, script_public_key: ScriptPublicKey::new(0, script_pub_key.clone()) },
            ],
            1615462089000,
            SubnetworkId::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            0,
            vec![],
        );

        let entries = vec![
            UtxoEntry {
                amount: 100,
                script_public_key: ScriptPublicKey::new(0, script_pub_key.clone()),
                block_daa_score: 0,
                is_coinbase: false,
            },
            UtxoEntry {
                amount: 200,
                script_public_key: ScriptPublicKey::new(0, script_pub_key.clone()),
                block_daa_score: 0,
                is_coinbase: false,
            },
            UtxoEntry {
                amount: 300,
                script_public_key: ScriptPublicKey::new(0, script_pub_key),
                block_daa_score: 0,
                is_coinbase: false,
            },
        ];
        let schnorr_key = secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, &secret_key.secret_bytes()).unwrap();
        let signed_tx = sign(MutableTransaction::with_entries(unsigned_tx, entries), schnorr_key);
        let populated_tx = signed_tx.as_verifiable();
        assert_eq!(tv.check_scripts(&populated_tx), Ok(()));
        assert_eq!(TransactionValidator::check_sig_op_counts(&populated_tx), Ok(()));
    }

    #[test]
    fn check_atomic_payload_context_rejects_non_owner_auth_script_class() {
        let params = MAINNET_PARAMS.clone();
        let tv = TransactionValidator::new(
            params.max_tx_inputs,
            params.max_tx_outputs,
            params.max_signature_script_len,
            params.max_script_public_key_len,
            params.ghostdag_k,
            params.coinbase_payload_script_public_key_max_len,
            params.coinbase_maturity,
            Arc::<TxScriptCacheCounters>::default(),
            MassCalculator::new(0, 0, 0, 0, 1),
            u64::MAX,
            0,
            8192,
        );

        let prev_tx_id = TransactionId::from_str("880eb9819a31821d9d2399e2f35e2433b72637e393d71ecc9b8d0250f49153c3").unwrap();
        let mut payload = Vec::new();
        payload.extend_from_slice(b"CAT");
        payload.push(1); // version
        payload.push(1); // transfer op
        payload.push(0); // flags
        payload.extend_from_slice(&0u16.to_le_bytes()); // auth_input_index
        payload.extend_from_slice(&1u64.to_le_bytes()); // nonce
        payload.extend_from_slice(&[1u8; 32]); // asset_id
        payload.extend_from_slice(&[2u8; 32]); // to_owner_id
        payload.extend_from_slice(&1u128.to_le_bytes()); // amount

        let tx = Transaction::new(
            0,
            vec![TransactionInput {
                previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id, index: 0 },
                signature_script: vec![],
                sequence: u64::MAX,
                sig_op_count: 0,
            }],
            vec![TransactionOutput { value: 1000, script_public_key: ScriptPublicKey::new(0, SmallVec::from(vec![0x51])) }],
            0,
            cryptix_consensus_core::subnets::SUBNETWORK_ID_PAYLOAD,
            0,
            payload,
        );
        let populated_tx = PopulatedTransaction::new(
            &tx,
            vec![UtxoEntry {
                amount: 2000,
                script_public_key: ScriptPublicKey::new(0, SmallVec::from(vec![0x51])),
                block_daa_score: 0,
                is_coinbase: false,
            }],
        );

        assert_eq!(
            tv.validate_populated_transaction_and_get_fee(&populated_tx, 0, TxValidationFlags::SkipScriptChecks, None),
            Err(TxRuleError::InvalidAtomicPayload(
                "auth input script public key is not a supported CAT owner authorization scheme (expected PubKey, PubKeyECDSA, or ScriptHash)"
                    .to_string()
            ))
        );
    }
}
