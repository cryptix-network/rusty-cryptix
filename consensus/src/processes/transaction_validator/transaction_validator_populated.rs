use crate::constants::{MAX_SOMPI, SEQUENCE_LOCK_TIME_DISABLED, SEQUENCE_LOCK_TIME_MASK};
use cryptix_consensus_core::{
    contract::{ContractPayload, validate_state_utxo_size},
    hashing::sighash::SigHashReusedValues,
    mass::Kip9Version,
    tx::{TransactionInput, VerifiableTransaction},
};
use cryptix_core::warn;
use cryptix_txscript::{get_sig_op_count, TxScriptEngine, is_contract_script, extract_contract_id};
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
    pub fn apply_contract_engine_if_needed(
        &self,
        tx: &impl VerifiableTransaction,
        pov_daa_score: u64,
    ) -> TxResult<()> {
        use cryptix_consensus_core::contract::{get_contract, ContractPayload, BlockContext, MAX_CONTRACT_STATE_SIZE};
        use cryptix_txscript::{is_contract_script, extract_contract_id};

        // Early exit if contracts not activated
        if pov_daa_score < self.contracts_hardfork_daa_score {
            cryptix_core::debug!("Skipping contract engine: DAA score {} < contracts_hardfork_daa_score {}", 
                                pov_daa_score, self.contracts_hardfork_daa_score);
            return Ok(());
        }

        let payload = tx.tx().payload.as_slice();
        // Early exit if not a contract payload
        if payload.len() < 3 || &payload[0..3] != b"CX\x01" {
            return Ok(());
        }

        // Parse contract payload (CBOR validity already checked in check_transaction_payload)
        let cp = match ContractPayload::parse(payload) {
            Ok(cp) => {
                cryptix_core::debug!("Contract payload parsed for engine: v={}, c={}, a={}, data_len={}", 
                                    cp.v, cp.c, cp.a, cp.d.len());
                cp
            },
            Err(e) => {
                cryptix_core::debug!("Contract payload parsing failed for engine: {:?}", e);
                return Err(e);
            }
        };
        
        let cid = cp.c;
        let action_id = cp.a;
        let data = cp.d.as_slice();
        cryptix_core::debug!("Applying contract engine for contract_id={}, action_id={}", cid, action_id);

        // Load contract from registry
        let contract = match get_contract(cid) {
            Some(c) => c,
            None => {
                cryptix_core::debug!("Unknown contract: {}", cid);
                return Err(TxRuleError::UnknownContract(cid));
            }
        };

        // Find the state input (validate_contract_state_rules already ensured exactly one exists for exec)
        let old_state: &[u8] = if cp.is_deploy() {
            cryptix_core::debug!("Deploy operation: starting with empty state");
            // Deploy: no state input, start with empty state
            &[]
        } else {
            // Execution: find the one state input, panic-safe extraction
            cryptix_core::debug!("Execution operation: finding state input");
            let mut found: Option<&cryptix_consensus_core::tx::UtxoEntry> = None;
            for (_, entry) in tx.populated_inputs() {
                let spk = entry.script_public_key.script();
                if is_contract_script(spk) {
                    let extracted = match extract_contract_id(spk) {
                        Some(id) => id,
                        None => {
                            cryptix_core::debug!("Failed to extract contract ID from input script");
                            return Err(TxRuleError::InvalidContractState(cid));
                        }
                    };
                    if extracted == cid {
                        found = Some(entry);
                        break;
                    }
                }
            }
            let state_entry = match found {
                Some(entry) => {
                    cryptix_core::debug!("Found state input with payload size: {}", entry.payload.len());
                    entry
                },
                None => {
                    cryptix_core::debug!("Missing contract state input");
                    return Err(TxRuleError::MissingContractState(cid));
                }
            };
            &state_entry.payload
        };

        // Find the state output (validate_contract_state_rules already ensured exactly one exists)
        cryptix_core::debug!("Finding state output");
        let new_state_from_tx: &[u8] = {
            // First, try to find a state output with a non-empty payload
            let mut non_empty_state: Option<&[u8]> = None;
            let mut empty_state: Option<&[u8]> = None;
            
            // Log all outputs for debugging
            for (i, out) in tx.outputs().iter().enumerate() {
                cryptix_core::debug!("Output #{}: value={}, payload_len={}", i, out.value, out.payload.len());
                
                let spk = out.script_public_key.script();
                if is_contract_script(spk) {
                    let extracted = match extract_contract_id(spk) {
                        Some(id) => id,
                        None => {
                            cryptix_core::debug!("Failed to extract contract ID from output script in output #{}", i);
                            continue; // Skip this output and try the next one
                        }
                    };
                    
                    if extracted == cid {
                        cryptix_core::debug!("Found contract state output #{} with matching CID={}, payload_len={}", 
                                           i, cid, out.payload.len());
                        
                        // Prefer non-empty state outputs
                        if !out.payload.is_empty() {
                            non_empty_state = Some(out.payload.as_slice());
                        } else if empty_state.is_none() {
                            empty_state = Some(out.payload.as_slice());
                        }
                    }
                }
            }
            
            // Prefer non-empty state if available
            let res = non_empty_state.or(empty_state);
            
            match res {
                Some(payload) => {
                    cryptix_core::debug!("Selected state output with payload size: {}", payload.len());
                    if !payload.is_empty() {
                        cryptix_core::debug!("State payload content: {:?}", payload);
                    }
                    payload
                },
                None => {
                    cryptix_core::debug!("Missing contract state output for CID={}", cid);
                    return Err(TxRuleError::MissingContractStateOutput)?;
                }
            }
        };

        // Build block context 
        let tx_id_hash = tx.tx().id();
        let mut tx_id = [0u8; 32];
        tx_id.copy_from_slice(tx_id_hash.as_bytes().as_slice());

        let ctx = BlockContext {
            block_height: 0,
            daa_score: pov_daa_score,
            block_time: 0,
            tx_id,
            input_index: 0,
            auth_addr: [0u8; 32], // validator-level context; RPC sets a real auth_addr, validator enforces presence via MissingAuthInput
        };

        cryptix_core::debug!("Executing contract engine: old_state_len={}, action_id={}, data_len={}", 
                            old_state.len(), action_id as u16, data.len());
        
        // Execute contract engine
        let engine_state = match contract.apply(old_state, action_id as u16, data, &ctx) {
            Ok(state) => {
                cryptix_core::debug!("Contract engine execution successful, new state size: {}", state.len());
                state
            },
            Err(e) => {
                cryptix_core::debug!("Contract engine execution failed: {:?}", e);
                return Err(map_contract_error(cid, action_id as u16, e));
            }
        };

        // Verify engine result size
        if engine_state.len() > MAX_CONTRACT_STATE_SIZE {
            cryptix_core::debug!("State too large: {} > {}", engine_state.len(), MAX_CONTRACT_STATE_SIZE);
            return Err(TxRuleError::StateTooLarge(engine_state.len(), MAX_CONTRACT_STATE_SIZE));
        }

        // Verify engine result matches transaction output state
        if engine_state.as_slice() != new_state_from_tx {
            cryptix_core::debug!("Invalid contract state: engine output doesn't match transaction output state");
            cryptix_core::debug!("Engine state len: {}, TX state len: {}", engine_state.len(), new_state_from_tx.len());
            if engine_state.len() < 100 && new_state_from_tx.len() < 100 {
                cryptix_core::debug!("Engine state: {:?}", engine_state.as_slice());
                cryptix_core::debug!("TX state: {:?}", new_state_from_tx);
            }
            return Err(TxRuleError::InvalidContractState(cid));
        }

        cryptix_core::debug!("Contract engine application successful for contract_id={}", cid);
        Ok(())
    }
    pub fn validate_populated_transaction_and_get_fee(
        &self,
        tx: &impl VerifiableTransaction,
        pov_daa_score: u64,
        flags: TxValidationFlags,
        mass_and_feerate_threshold: Option<(u64, f64)>,
    ) -> TxResult<u64> {
        self.check_transaction_coinbase_maturity(tx, pov_daa_score)?;
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
        self.check_transaction_payload(tx, pov_daa_score)?;
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

    fn check_transaction_payload(&self, tx: &impl VerifiableTransaction, pov_daa_score: u64) -> TxResult<()> {
        // Coinbase transactions can always have payloads (no size limit check here)
        // Note: Coinbase payloads are never interpreted as contract payloads, even if they start with "CX\x01"
        if tx.is_coinbase() {
            return Ok(());
        }

        // Non-coinbase transactions can have payloads only after the hardfork activation
        if pov_daa_score < self.non_coinbase_payload_activation_daa_score {
            if !tx.tx().payload.is_empty() {
                cryptix_core::debug!("Payload rejected: DAA score {} < non_coinbase_payload_activation_daa_score {}", 
                                    pov_daa_score, self.non_coinbase_payload_activation_daa_score);
                return Err(TxRuleError::NonCoinbaseTxHasPayload);
            }
        } else {
            // After hardfork activation, check payload size limit
            let payload_len = tx.tx().payload.len();
            if payload_len > self.max_non_coinbase_payload_len {
                cryptix_core::debug!("Payload too large: {} > max_non_coinbase_payload_len {}", 
                                    payload_len, self.max_non_coinbase_payload_len);
                return Err(TxRuleError::NonCoinbasePayloadTooLarge(payload_len, self.max_non_coinbase_payload_len));
            }

            // After contracts hardfork activation, check for contract magic bytes and parse CBOR
            if pov_daa_score >= self.contracts_hardfork_daa_score {
                let payload = &tx.tx().payload;
                if payload.len() >= 3 && payload[0..3] == [b'C', b'X', 0x01] {
                    // Contract payload detected - parse and validate CBOR
                    cryptix_core::debug!("Contract payload detected, parsing CBOR. Payload length: {}", payload.len());
                    match ContractPayload::parse(payload) {
                        Ok(cp) => {
                            cryptix_core::debug!("Contract payload parsed successfully: v={}, c={}, a={}, data_len={}", 
                                                cp.v, cp.c, cp.a, cp.d.len());
                        },
                        Err(e) => {
                            cryptix_core::debug!("Contract payload parsing failed: {:?}", e);
                            return Err(e);
                        }
                    }
                    // CBOR-only validation. Contract state rules (deploy/exec) are validated
                    // later in UTXO context (validate_transaction_in_utxo_context) where inputs are available.
                    return Ok(());
                    // Note: ContractAlreadyDeployed is checked in validate_transaction_in_utxo_context
                }
            } else {
                cryptix_core::debug!("Contract hardfork not activated: DAA score {} < contracts_hardfork_daa_score {}", 
                                    pov_daa_score, self.contracts_hardfork_daa_score);
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

    pub fn validate_contract_state_rules(&self, tx: &impl VerifiableTransaction, pov_daa_score: u64) -> TxResult<()> {
        // Enforce deploy/exec rules only after contracts hardfork activation
        if pov_daa_score < self.contracts_hardfork_daa_score {
            return Ok(());
        }

        let payload = tx.tx().payload.as_slice();

        // If there exists any contract state input, a valid contract payload is required (deploy/exec).
        // Otherwise, spending contract state without execution is forbidden.
        let has_any_contract_input = tx.populated_inputs().any(|(_, entry)| {
            let spk = entry.script_public_key.script();
            is_contract_script(spk)
        });

        // If not a contract payload
        if payload.len() < 3 || &payload[0..3] != b"CX\x01" {
            // If there are contract state inputs, forbid spending without execution payload
            if has_any_contract_input {
                return Err(TxRuleError::ContractStateSpendWithoutExecution);
            }
            // Otherwise nothing to validate
            return Ok(());
        }

        // Parse payload; CBOR validity was already checked earlier but parsing again is safe and cheap here
        let contract_payload = ContractPayload::parse(payload)?;
        let cid = contract_payload.c;

        // Helper: count matching state inputs, ensuring robust contract id extraction
        let count_matching_state_inputs = || -> TxResult<usize> {
            let mut cnt = 0usize;
            for (_, entry) in tx.populated_inputs() {
                let spk = entry.script_public_key.script();
                if is_contract_script(spk) {
                    let extracted = extract_contract_id(spk).ok_or(TxRuleError::InvalidContractState(cid))?;
                    if extracted == cid {
                        cnt += 1;
                    }
                }
            }
            Ok(cnt)
        };

        let mut matching_state_outputs: Vec<&cryptix_consensus_core::tx::TransactionOutput> = {
            let mut v = Vec::new();
            for out in tx.outputs().iter() {
                let spk = out.script_public_key.script();
                if is_contract_script(spk) {
                    let extracted = match extract_contract_id(spk) {
                        Some(id) => id,
                        None => return Err(TxRuleError::InvalidContractState(cid)),
                    };
                    if extracted == cid {
                        v.push(out);
                    }
                }
            }
            v
        };

        if contract_payload.is_deploy() {
            // DEPLOY: exactly one state output OP_CONTRACT<cid>, value == 0, payload <= 8KB
            if matching_state_outputs.is_empty() {
                return Err(TxRuleError::MissingContractStateOutput);
            }
            if matching_state_outputs.len() > 1 {
                return Err(TxRuleError::MultipleStateUtxos(cid));
            }
            let state_out = matching_state_outputs.remove(0);
            if state_out.value != 0 {
                return Err(TxRuleError::NonZeroContractStateValue(cid, state_out.value));
            }
            validate_state_utxo_size(&state_out.payload)?;
        } else {
            // EXECUTION (action_id > 0):
            // Inputs: exactly one state input OP_CONTRACT<cid>
            let input_count = count_matching_state_inputs()?;
            if input_count == 0 {
                return Err(TxRuleError::MissingContractState(cid));
            }
            if input_count > 1 {
                return Err(TxRuleError::MultipleStateUtxos(cid));
            }

            // Outputs: exactly one state output OP_CONTRACT<cid>, value == 0, payload <= 8KB
            if matching_state_outputs.is_empty() {
                return Err(TxRuleError::MissingContractStateOutput);
            }
            if matching_state_outputs.len() > 1 {
                return Err(TxRuleError::MultipleStateUtxos(cid));
            }
            let state_out = matching_state_outputs.remove(0);
            if state_out.value != 0 {
                return Err(TxRuleError::NonZeroContractStateValue(cid, state_out.value));
            }
            validate_state_utxo_size(&state_out.payload)?;
        }

        // Enforce presence of at least one non-contract auth input.
        // Note: Signature validity is verified later by check_scripts; here we only require existence.
        if !contract_payload.is_deploy() {
            let has_non_contract_input = tx.populated_inputs().any(|(_, entry)| {
                let spk = entry.script_public_key.script();
                !is_contract_script(spk)
            });
            if !has_non_contract_input {
                return Err(TxRuleError::MissingAuthInput);
            }
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
            //  Skip script execution for contract state UTXOs. These are validated by contract state rules + engine.
            let spk = entry.script_public_key.script();
            if is_contract_script(spk) {
                continue;
            }
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

fn map_contract_error(cid: u64, action_id: u16, e: cryptix_consensus_core::contract::ContractError) -> TxRuleError {
    use cryptix_consensus_core::contract::{ContractError, MAX_CONTRACT_STATE_SIZE};
    match e {
        ContractError::InvalidAction => TxRuleError::InvalidContractAction(cid as u64, action_id),
        ContractError::InvalidState => TxRuleError::InvalidContractState(cid),
        ContractError::StateTooLarge => TxRuleError::StateTooLarge(MAX_CONTRACT_STATE_SIZE + 1, MAX_CONTRACT_STATE_SIZE),
        ContractError::Custom(code) => TxRuleError::ContractCustomError(cid, code),
    }
}

#[cfg(test)]
mod tests {
    use super::super::errors::TxRuleError;
    use core::str::FromStr;
    use itertools::Itertools;
    use cryptix_consensus_core::sign::sign;
    use cryptix_consensus_core::subnets::{SubnetworkId, SUBNETWORK_ID_NATIVE};
    use cryptix_consensus_core::tx::{MutableTransaction, PopulatedTransaction, scriptvec, ScriptVec, TransactionId, UtxoEntry};
    use cryptix_consensus_core::tx::{ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput};
    use cryptix_core::assert_match;
    use cryptix_txscript_errors::TxScriptError;
    use secp256k1::Secp256k1;
    use smallvec::SmallVec;
    use std::iter::once;

    use crate::{params::MAINNET_PARAMS, processes::transaction_validator::TransactionValidator};

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
                TransactionOutput { value: 10360487799, script_public_key: ScriptPublicKey::new(0, script_pub_key_2), payload: vec![] },
                TransactionOutput { value: 10518958752, script_public_key: ScriptPublicKey::new(0, script_pub_key_1.clone()), payload: vec![] },
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
                payload: Vec::new(),
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
                TransactionOutput { value: 10360487799, script_public_key: ScriptPublicKey::new(0, script_pub_key_2.clone()) ,
                    payload: vec![] },
                TransactionOutput { value: 10518958752, script_public_key: ScriptPublicKey::new(0, script_pub_key_1) ,
                  payload: vec![] },
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
                payload: Vec::new(),
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
                TransactionOutput { value: 10000000000000, script_public_key: ScriptPublicKey::new(0, script_pub_key_2), payload: vec![] },
                TransactionOutput { value: 2792999990000, script_public_key: ScriptPublicKey::new(0, script_pub_key_1.clone()), payload: vec![] },
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
                payload: Vec::new(),
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
                TransactionOutput { value: 10000000000000, script_public_key: ScriptPublicKey::new(0, script_pub_key_2), payload: vec![] },
                TransactionOutput { value: 2792999990000, script_public_key: ScriptPublicKey::new(0, script_pub_key_1.clone()), payload: vec![] },
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
                payload: Vec::new(),
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
                TransactionOutput { value: 10000000000000, script_public_key: ScriptPublicKey::new(0, script_pub_key_2), payload: vec![] },
                TransactionOutput { value: 2792999990000, script_public_key: ScriptPublicKey::new(0, script_pub_key_1.clone()), payload: vec![] },
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
                payload: Vec::new(),
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
                TransactionOutput { value: 10000000000000, script_public_key: ScriptPublicKey::new(0, script_pub_key_2), payload: vec![] },
                TransactionOutput { value: 2792999990000, script_public_key: ScriptPublicKey::new(0, script_pub_key_1.clone()), payload: vec![] },
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
                payload: Vec::new(),
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
            vec![TransactionOutput { value: 2792999990000, script_public_key: ScriptPublicKey::new(0, script_pub_key_1.clone()), payload: vec![] }],
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
                payload: Vec::new(),
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
                TransactionOutput { value: 300, script_public_key: ScriptPublicKey::new(0, script_pub_key.clone()), payload: vec![] },
                TransactionOutput { value: 300, script_public_key: ScriptPublicKey::new(0, script_pub_key.clone()), payload: vec![] },
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
                payload: Vec::new(),
            },
            UtxoEntry {
                amount: 200,
                script_public_key: ScriptPublicKey::new(0, script_pub_key.clone()),
                block_daa_score: 0,
                is_coinbase: false,
                payload: Vec::new(),
            },
            UtxoEntry {
                amount: 300,
                script_public_key: ScriptPublicKey::new(0, script_pub_key),
                block_daa_score: 0,
                is_coinbase: false,
                payload: Vec::new(),
            },
        ];
        let schnorr_key = secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, &secret_key.secret_bytes()).unwrap();
        let signed_tx = sign(MutableTransaction::with_entries(unsigned_tx, entries), schnorr_key);
        let populated_tx = signed_tx.as_verifiable();
        assert_eq!(tv.check_scripts(&populated_tx), Ok(()));
        assert_eq!(TransactionValidator::check_sig_op_counts(&populated_tx), Ok(()));
    }

    #[test]
    fn test_payload_validation_populated_before_hardfork() {
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

        let prev_tx_id = TransactionId::from_str("880eb9819a31821d9d2399e2f35e2433b72637e393d71ecc9b8d0250f49153c3").unwrap();
        let tx = Transaction::new(
            0,
            vec![TransactionInput {
                previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id, index: 0 },
                signature_script: vec![],
                sequence: 0,
                sig_op_count: 0,
            }],
            vec![TransactionOutput { value: 100, script_public_key: ScriptPublicKey::new(0, scriptvec!(0x51)), // OP_TRUE
            
             payload: vec![] }],
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            vec![1, 2, 3], // Small payload
        );

        let populated_tx = PopulatedTransaction::new(
            &tx,
            vec![UtxoEntry {
                amount: 100,
                script_public_key: ScriptPublicKey::new(0, scriptvec!(0x51)),
                block_daa_score: 0,
                is_coinbase: false,
                payload: Vec::new(),
            }],
        );

        // Before hardfork (DAA score < 156_000_000), payload should fail
        let pov_daa_score = 156_000_000 - 1;
        assert_match!(tv.check_transaction_payload(&populated_tx, pov_daa_score), Err(TxRuleError::NonCoinbaseTxHasPayload));
    }

    #[test]
    fn test_payload_validation_populated_after_hardfork() {
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

        let prev_tx_id = TransactionId::from_str("880eb9819a31821d9d2399e2f35e2433b72637e393d71ecc9b8d0250f49153c3").unwrap();

        // Test: Payload within 35 KB limit should pass after hardfork
        let tx = Transaction::new(
            0,
            vec![TransactionInput {
                previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id, index: 0 },
                signature_script: vec![],
                sequence: 0,
                sig_op_count: 0,
            }],
            vec![TransactionOutput { value: 100, script_public_key: ScriptPublicKey::new(0, scriptvec!(0x51)), // OP_TRUE
             payload: vec![] }],
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            vec![1; 35 * 1024], // Exactly 35 KB payload
        );

        let populated_tx = PopulatedTransaction::new(
            &tx,
            vec![UtxoEntry {
                amount: 100,
                script_public_key: ScriptPublicKey::new(0, scriptvec!(0x51)),
                block_daa_score: 0,
                is_coinbase: false,
                payload: Vec::new(),
            }],
        );

        // After hardfork (DAA score >= 156_000_000), payload within limit should pass
        let pov_daa_score = 156_000_000;
        assert_eq!(tv.check_transaction_payload(&populated_tx, pov_daa_score), Ok(()));
    }

    #[test]
    fn test_payload_validation_populated_over_limit() {
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

        let prev_tx_id = TransactionId::from_str("880eb9819a31821d9d2399e2f35e2433b72637e393d71ecc9b8d0250f49153c3").unwrap();

        // Test: Payload over 35 KB limit should fail even after hardfork
        let tx = Transaction::new(
            0,
            vec![TransactionInput {
                previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id, index: 0 },
                signature_script: vec![],
                sequence: 0,
                sig_op_count: 0,
            }],
            vec![TransactionOutput { value: 100, script_public_key: ScriptPublicKey::new(0, scriptvec!(0x51)), // OP_TRUE
            
            payload: vec![] }],
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            vec![1; 35 * 1024 + 1], // Over 35 KB payload
        );

        let populated_tx = PopulatedTransaction::new(
            &tx,
            vec![UtxoEntry {
                amount: 100,
                script_public_key: ScriptPublicKey::new(0, scriptvec!(0x51)),
                block_daa_score: 0,
                is_coinbase: false,
                payload: Vec::new(),
            }],
        );

        let pov_daa_score = 156_000_000;
        let _expected_payload_len = 35 * 1024 + 1;
        let _expected_max_len = 35 * 1024;
        assert_match!(tv.check_transaction_payload(&populated_tx, pov_daa_score), Err(TxRuleError::NonCoinbasePayloadTooLarge(_, _)));
    }


  #[test]
    fn test_contract_prefix_after_hardfork() {
        let mut params = MAINNET_PARAMS.clone();

        params.non_coinbase_payload_activation_daa_score = 0;
        params.max_non_coinbase_payload_len = 40 * 1024; 
        params.contracts_hardfork_daa_score = 100;

        let mut tv = TransactionValidator::new_for_tests(
            params.max_tx_inputs,
            params.max_tx_outputs,
            params.max_signature_script_len,
            params.max_script_public_key_len,
            params.ghostdag_k,
            params.coinbase_payload_script_public_key_max_len,
            params.coinbase_maturity,
            Default::default(),
        );

        tv.non_coinbase_payload_activation_daa_score = params.non_coinbase_payload_activation_daa_score;
        tv.max_non_coinbase_payload_len = params.max_non_coinbase_payload_len;
        tv.contracts_hardfork_daa_score = params.contracts_hardfork_daa_score;

        let prev_tx_id = TransactionId::from_str(
            "880eb9819a31821d9d2399e2f35e2433b72637e393d71ecc9b8d0250f49153c3"
        ).unwrap();

        let tx = Transaction::new(
            0,
            vec![TransactionInput {
                previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id, index: 0 },
                signature_script: vec![],
                sequence: 0,
                sig_op_count: 0,
            }],
            vec![TransactionOutput { value: 100, script_public_key: ScriptPublicKey::new(0, scriptvec!(0x51)),
             payload: vec![] }],
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            vec![b'C', b'X', 0x01, 0xAA],
        );

        let populated_tx = PopulatedTransaction::new(
            &tx,
            vec![UtxoEntry {
                amount: 100,
                script_public_key: ScriptPublicKey::new(0, scriptvec!(0x51)),
                block_daa_score: 0,
                is_coinbase: false,
                payload: Vec::new(),
            }],
        );

        let pov_daa_score = 100;

        assert_match!(
            tv.check_transaction_payload(&populated_tx, pov_daa_score),
            Err(TxRuleError::BadContractPayload)
        );
    }

    #[test]
    fn test_contract_cbor_parsing_valid() {
        use cryptix_consensus_core::contract::ContractPayload;

        let mut params = MAINNET_PARAMS.clone();
        params.non_coinbase_payload_activation_daa_score = 0;
        params.max_non_coinbase_payload_len = 40 * 1024;
        params.contracts_hardfork_daa_score = 100;

        let mut tv = TransactionValidator::new_for_tests(
            params.max_tx_inputs,
            params.max_tx_outputs,
            params.max_signature_script_len,
            params.max_script_public_key_len,
            params.ghostdag_k,
            params.coinbase_payload_script_public_key_max_len,
            params.coinbase_maturity,
            Default::default(),
        );

        tv.non_coinbase_payload_activation_daa_score = params.non_coinbase_payload_activation_daa_score;
        tv.max_non_coinbase_payload_len = params.max_non_coinbase_payload_len;
        tv.contracts_hardfork_daa_score = params.contracts_hardfork_daa_score;

        let prev_tx_id = TransactionId::from_str(
            "880eb9819a31821d9d2399e2f35e2433b72637e393d71ecc9b8d0250f49153c3"
        ).unwrap();

        // Create valid contract payload
        let contract_payload = ContractPayload {
            v: 1,
            c: 1234,
            a: 5,
            d: vec![0xAA, 0xBB, 0xCC],
        };
        let encoded_payload = contract_payload.encode().unwrap();

        let tx = Transaction::new(
            0,
            vec![TransactionInput {
                previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id, index: 0 },
                signature_script: vec![],
                sequence: 0,
                sig_op_count: 0,
            }],
            vec![TransactionOutput { value: 100, script_public_key: ScriptPublicKey::new(0, scriptvec!(0x51)),

             payload: vec![] }],
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            encoded_payload,
        );

        let populated_tx = PopulatedTransaction::new(
            &tx,
            vec![UtxoEntry {
                amount: 100,
                script_public_key: ScriptPublicKey::new(0, scriptvec!(0x51)),
                block_daa_score: 0,
                is_coinbase: false,
                payload: Vec::new(),
            }],
        );

        let pov_daa_score = 100;

        // Valid CBOR should pass (though contract execution will fail in Phase 3)
        assert_eq!(tv.check_transaction_payload(&populated_tx, pov_daa_score), Ok(()));
    }

    #[test]
    fn test_contract_cbor_parsing_invalid() {
        let mut params = MAINNET_PARAMS.clone();
        params.non_coinbase_payload_activation_daa_score = 0;
        params.max_non_coinbase_payload_len = 40 * 1024;
        params.contracts_hardfork_daa_score = 100;

        let mut tv = TransactionValidator::new_for_tests(
            params.max_tx_inputs,
            params.max_tx_outputs,
            params.max_signature_script_len,
            params.max_script_public_key_len,
            params.ghostdag_k,
            params.coinbase_payload_script_public_key_max_len,
            params.coinbase_maturity,
            Default::default(),
        );

        tv.non_coinbase_payload_activation_daa_score = params.non_coinbase_payload_activation_daa_score;
        tv.max_non_coinbase_payload_len = params.max_non_coinbase_payload_len;
        tv.contracts_hardfork_daa_score = params.contracts_hardfork_daa_score;

        let prev_tx_id = TransactionId::from_str(
            "880eb9819a31821d9d2399e2f35e2433b72637e393d71ecc9b8d0250f49153c3"
        ).unwrap();

        // Invalid CBOR after magic bytes
        let invalid_payload = vec![b'C', b'X', 0x01, 0xFF, 0xFF, 0xFF];

        let tx = Transaction::new(
            0,
            vec![TransactionInput {
                previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id, index: 0 },
                signature_script: vec![],
                sequence: 0,
                sig_op_count: 0,
            }],
            vec![TransactionOutput { value: 100, script_public_key: ScriptPublicKey::new(0, scriptvec!(0x51)),
            
             payload: vec![] }],
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            invalid_payload,
        );

        let populated_tx = PopulatedTransaction::new(
            &tx,
            vec![UtxoEntry {
                amount: 100,
                script_public_key: ScriptPublicKey::new(0, scriptvec!(0x51)),
                block_daa_score: 0,
                is_coinbase: false,
                payload: Vec::new(),
            }],
        );

        let pov_daa_score = 100;

        // Invalid CBOR should fail
        assert_match!(
            tv.check_transaction_payload(&populated_tx, pov_daa_score),
            Err(TxRuleError::BadContractPayload)
        );
    }

    #[test]
    fn test_deploy_missing_state_output() {
        use cryptix_consensus_core::contract::ContractPayload;
        use cryptix_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
        use cryptix_consensus_core::tx::{ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry, PopulatedTransaction, scriptvec, ScriptVec};
        use cryptix_txscript::pay_to_contract_script;
        use core::str::FromStr;
        use crate::params::MAINNET_PARAMS;

        let mut params = MAINNET_PARAMS.clone();
        params.non_coinbase_payload_activation_daa_score = 0;
        params.max_non_coinbase_payload_len = 40 * 1024;
        params.contracts_hardfork_daa_score = 100;

        let mut tv = TransactionValidator::new_for_tests(
            params.max_tx_inputs,
            params.max_tx_outputs,
            params.max_signature_script_len,
            params.max_script_public_key_len,
            params.ghostdag_k,
            params.coinbase_payload_script_public_key_max_len,
            params.coinbase_maturity,
            Default::default(),
        );

        tv.non_coinbase_payload_activation_daa_score = params.non_coinbase_payload_activation_daa_score;
        tv.max_non_coinbase_payload_len = params.max_non_coinbase_payload_len;
        tv.contracts_hardfork_daa_score = params.contracts_hardfork_daa_score;

        let prev_tx_id = TransactionId::from_str(
            "880eb9819a31821d9d2399e2f35e2433b72637e393d71ecc9b8d0250f49153c3"
        ).unwrap();

        let cid = 42u64;
        let contract_payload = ContractPayload { v: 1, c: cid, a: 0, d: vec![0x01, 0x02] };
        let encoded_payload = contract_payload.encode().unwrap();

        // No OP_CONTRACT outputs -> should fail with MissingContractStateOutput
        let tx = Transaction::new(
            0,
            vec![TransactionInput {
                previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id, index: 0 },
                signature_script: vec![],
                sequence: 0,
                sig_op_count: 0,
            }],
            vec![TransactionOutput {
                value: 100,
                script_public_key: ScriptPublicKey::new(0, scriptvec!(0x51)), // OP_TRUE
                payload: vec![],
            }],
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            encoded_payload,
        );

        let populated_tx = PopulatedTransaction::new(
            &tx,
            vec![UtxoEntry {
                amount: 100,
                script_public_key: ScriptPublicKey::new(0, scriptvec!(0x51)),
                block_daa_score: 0,
                is_coinbase: false,
                payload: Vec::new(),
            }],
        );

        let pov_daa_score = 100;
        assert_match!(tv.validate_contract_state_rules(&populated_tx, pov_daa_score), Err(TxRuleError::MissingContractStateOutput));
    }

    #[test]
    fn test_deploy_multiple_state_outputs() {
        use cryptix_consensus_core::contract::ContractPayload;
        use cryptix_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
        use cryptix_consensus_core::tx::{ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry, PopulatedTransaction, ScriptVec};
        use cryptix_txscript::pay_to_contract_script;
        use core::str::FromStr;
        use crate::params::MAINNET_PARAMS;

        let mut params = MAINNET_PARAMS.clone();
        params.non_coinbase_payload_activation_daa_score = 0;
        params.max_non_coinbase_payload_len = 40 * 1024;
        params.contracts_hardfork_daa_score = 100;

        let mut tv = TransactionValidator::new_for_tests(
            params.max_tx_inputs,
            params.max_tx_outputs,
            params.max_signature_script_len,
            params.max_script_public_key_len,
            params.ghostdag_k,
            params.coinbase_payload_script_public_key_max_len,
            params.coinbase_maturity,
            Default::default(),
        );

        tv.non_coinbase_payload_activation_daa_score = params.non_coinbase_payload_activation_daa_score;
        tv.max_non_coinbase_payload_len = params.max_non_coinbase_payload_len;
        tv.contracts_hardfork_daa_score = params.contracts_hardfork_daa_score;

        let prev_tx_id = TransactionId::from_str(
            "880eb9819a31821d9d2399e2f35e2433b72637e393d71ecc9b8d0250f49153c3"
        ).unwrap();

        let cid = 4242u64;
        let contract_payload = ContractPayload { v: 1, c: cid, a: 0, d: vec![] };
        let encoded_payload = contract_payload.encode().unwrap();

        let spk = ScriptVec::from_slice(&pay_to_contract_script(cid));

        // Two OP_CONTRACT outputs with same cid -> MultipleStateUtxos
        let tx = Transaction::new(
            0,
            vec![TransactionInput {
                previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id, index: 0 },
                signature_script: vec![],
                sequence: 0,
                sig_op_count: 0,
            }],
            vec![
                TransactionOutput { value: 0, script_public_key: ScriptPublicKey::new(0, spk.clone()), payload: vec![] },
                TransactionOutput { value: 0, script_public_key: ScriptPublicKey::new(0, spk.clone()), payload: vec![] },
            ],
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            encoded_payload,
        );

        let populated_tx = PopulatedTransaction::new(
            &tx,
            vec![UtxoEntry { amount: 100, script_public_key: ScriptPublicKey::new(0, ScriptVec::from_slice(&[0x51])), block_daa_score: 0, is_coinbase: false, payload: Vec::new() }],
        );

        let pov_daa_score = 100;
        assert_match!(tv.validate_contract_state_rules(&populated_tx, pov_daa_score), Err(TxRuleError::MultipleStateUtxos(cid)));
    }

    #[test]
    fn test_deploy_non_zero_value_state_output() {
        use cryptix_consensus_core::contract::ContractPayload;
        use cryptix_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
        use cryptix_consensus_core::tx::{ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry, PopulatedTransaction, ScriptVec};
        use cryptix_txscript::pay_to_contract_script;
        use core::str::FromStr;
        use crate::params::MAINNET_PARAMS;

        let mut params = MAINNET_PARAMS.clone();
        params.non_coinbase_payload_activation_daa_score = 0;
        params.max_non_coinbase_payload_len = 40 * 1024;
        params.contracts_hardfork_daa_score = 100;

        let mut tv = TransactionValidator::new_for_tests(
            params.max_tx_inputs,
            params.max_tx_outputs,
            params.max_signature_script_len,
            params.max_script_public_key_len,
            params.ghostdag_k,
            params.coinbase_payload_script_public_key_max_len,
            params.coinbase_maturity,
            Default::default(),
        );

        tv.non_coinbase_payload_activation_daa_score = params.non_coinbase_payload_activation_daa_score;
        tv.max_non_coinbase_payload_len = params.max_non_coinbase_payload_len;
        tv.contracts_hardfork_daa_score = params.contracts_hardfork_daa_score;

        let prev_tx_id = TransactionId::from_str(
            "880eb9819a31821d9d2399e2f35e2433b72637e393d71ecc9b8d0250f49153c3"
        ).unwrap();

        let cid = 7u64;
        let contract_payload = ContractPayload { v: 1, c: cid, a: 0, d: vec![] };
        let encoded_payload = contract_payload.encode().unwrap();

        let spk = ScriptVec::from_slice(&pay_to_contract_script(cid));

        // Single OP_CONTRACT output but value != 0 -> NonZeroContractStateValue
        let tx = Transaction::new(
            0,
            vec![TransactionInput {
                previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id, index: 0 },
                signature_script: vec![],
                sequence: 0,
                sig_op_count: 0,
            }],
            vec![TransactionOutput { value: 1, script_public_key: ScriptPublicKey::new(0, spk), payload: vec![] }],
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            encoded_payload,
        );

        let populated_tx = PopulatedTransaction::new(
            &tx,
            vec![UtxoEntry { amount: 1, script_public_key: ScriptPublicKey::new(0, ScriptVec::from_slice(&[0x51])), block_daa_score: 0, is_coinbase: false, payload: Vec::new() }],
        );

        let pov_daa_score = 100;
        assert_match!(tv.validate_contract_state_rules(&populated_tx, pov_daa_score), Err(TxRuleError::NonZeroContractStateValue(cid, 1)));
    }

    #[test]
    fn test_deploy_state_payload_too_large() {
        use cryptix_consensus_core::contract::{ContractPayload, MAX_CONTRACT_STATE_SIZE};
        use cryptix_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
        use cryptix_consensus_core::tx::{ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry, PopulatedTransaction, ScriptVec};
        use cryptix_txscript::pay_to_contract_script;
        use core::str::FromStr;
        use crate::params::MAINNET_PARAMS;

        let mut params = MAINNET_PARAMS.clone();
        params.non_coinbase_payload_activation_daa_score = 0;
        params.max_non_coinbase_payload_len = 40 * 1024;
        params.contracts_hardfork_daa_score = 100;

        let mut tv = TransactionValidator::new_for_tests(
            params.max_tx_inputs,
            params.max_tx_outputs,
            params.max_signature_script_len,
            params.max_script_public_key_len,
            params.ghostdag_k,
            params.coinbase_payload_script_public_key_max_len,
            params.coinbase_maturity,
            Default::default(),
        );

        tv.non_coinbase_payload_activation_daa_score = params.non_coinbase_payload_activation_daa_score;
        tv.max_non_coinbase_payload_len = params.max_non_coinbase_payload_len;
        tv.contracts_hardfork_daa_score = params.contracts_hardfork_daa_score;

        let prev_tx_id = TransactionId::from_str(
            "880eb9819a31821d9d2399e2f35e2433b72637e393d71ecc9b8d0250f49153c3"
        ).unwrap();

        let cid = 9999u64;
        let contract_payload = ContractPayload { v: 1, c: cid, a: 0, d: vec![] };
        let encoded_payload = contract_payload.encode().unwrap();

        let spk = ScriptVec::from_slice(&pay_to_contract_script(cid));
        let too_large_state = vec![0u8; MAX_CONTRACT_STATE_SIZE + 1];

        let tx = Transaction::new(
            0,
            vec![TransactionInput {
                previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id, index: 0 },
                signature_script: vec![],
                sequence: 0,
                sig_op_count: 0,
            }],
            vec![TransactionOutput { value: 0, script_public_key: ScriptPublicKey::new(0, spk), payload: too_large_state }],
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            encoded_payload,
        );

        let populated_tx = PopulatedTransaction::new(
            &tx,
            vec![UtxoEntry {
                amount: 0,
                script_public_key: ScriptPublicKey::new(0, ScriptVec::from_slice(&[0x51])),
                block_daa_score: 0,
                is_coinbase: false,
                payload: Vec::new(),
            }],
        );

        let pov_daa_score = 100;
        assert_match!(tv.validate_contract_state_rules(&populated_tx, pov_daa_score), Err(TxRuleError::StateTooLarge(_, _)));
    }

    #[test]
    fn test_deploy_state_payload_max_ok() {
        use cryptix_consensus_core::contract::{ContractPayload, MAX_CONTRACT_STATE_SIZE};
        use cryptix_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
        use cryptix_consensus_core::tx::{ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry, PopulatedTransaction, ScriptVec};
        use cryptix_txscript::pay_to_contract_script;
        use core::str::FromStr;
        use crate::params::MAINNET_PARAMS;

        let mut params = MAINNET_PARAMS.clone();
        params.non_coinbase_payload_activation_daa_score = 0;
        params.max_non_coinbase_payload_len = 40 * 1024;
        params.contracts_hardfork_daa_score = 100;

        let mut tv = TransactionValidator::new_for_tests(
            params.max_tx_inputs,
            params.max_tx_outputs,
            params.max_signature_script_len,
            params.max_script_public_key_len,
            params.ghostdag_k,
            params.coinbase_payload_script_public_key_max_len,
            params.coinbase_maturity,
            Default::default(),
        );

        tv.non_coinbase_payload_activation_daa_score = params.non_coinbase_payload_activation_daa_score;
        tv.max_non_coinbase_payload_len = params.max_non_coinbase_payload_len;
        tv.contracts_hardfork_daa_score = params.contracts_hardfork_daa_score;

        let prev_tx_id = TransactionId::from_str(
            "880eb9819a31821d9d2399e2f35e2433b72637e393d71ecc9b8d0250f49153c3"
        ).unwrap();

        let cid = 424242u64;
        let contract_payload = ContractPayload { v: 1, c: cid, a: 0, d: vec![] };
        let encoded_payload = contract_payload.encode().unwrap();

        let spk = ScriptVec::from_slice(&pay_to_contract_script(cid));
        let state = vec![0u8; MAX_CONTRACT_STATE_SIZE];

        let tx = Transaction::new(
            0,
            vec![TransactionInput {
                previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id, index: 0 },
                signature_script: vec![],
                sequence: 0,
                sig_op_count: 0,
            }],
            vec![TransactionOutput { value: 0, script_public_key: ScriptPublicKey::new(0, spk), payload: state }],
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            encoded_payload,
        );

        let populated_tx = PopulatedTransaction::new(
            &tx,
            vec![UtxoEntry {
                amount: 0,
                script_public_key: ScriptPublicKey::new(0, ScriptVec::from_slice(&[0x51])),
                block_daa_score: 0,
                is_coinbase: false,
                payload: Vec::new(),
            }],
        );

        let pov_daa_score = 100;
        // Exactly at limit should be OK
        assert_eq!(tv.check_transaction_payload(&populated_tx, pov_daa_score), Ok(()));
    }

    #[test]
    fn test_deploy_with_other_contract_outputs_ok() {
        use cryptix_consensus_core::contract::ContractPayload;
        use cryptix_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
        use cryptix_consensus_core::tx::{ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry, PopulatedTransaction, ScriptVec};
        use cryptix_txscript::pay_to_contract_script;
        use core::str::FromStr;
        use crate::params::MAINNET_PARAMS;

        let mut params = MAINNET_PARAMS.clone();
        params.non_coinbase_payload_activation_daa_score = 0;
        params.max_non_coinbase_payload_len = 40 * 1024;
        params.contracts_hardfork_daa_score = 100;

        let mut tv = TransactionValidator::new_for_tests(
            params.max_tx_inputs,
            params.max_tx_outputs,
            params.max_signature_script_len,
            params.max_script_public_key_len,
            params.ghostdag_k,
            params.coinbase_payload_script_public_key_max_len,
            params.coinbase_maturity,
            Default::default(),
        );

        tv.non_coinbase_payload_activation_daa_score = params.non_coinbase_payload_activation_daa_score;
        tv.max_non_coinbase_payload_len = params.max_non_coinbase_payload_len;
        tv.contracts_hardfork_daa_score = params.contracts_hardfork_daa_score;

        let prev_tx_id = TransactionId::from_str(
            "880eb9819a31821d9d2399e2f35e2433b72637e393d71ecc9b8d0250f49153c3"
        ).unwrap();

        let cid = 55u64;
        let other_cid = 66u64;
        let contract_payload = ContractPayload { v: 1, c: cid, a: 0, d: vec![] };
        let encoded_payload = contract_payload.encode().unwrap();

        let spk = ScriptVec::from_slice(&pay_to_contract_script(cid));
        let spk_other = ScriptVec::from_slice(&pay_to_contract_script(other_cid));

        // Exactly 1 output for cid, plus another OP_CONTRACT for a different contract id -> should pass
        let tx = Transaction::new(
            0,
            vec![TransactionInput {
                previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id, index: 0 },
                signature_script: vec![],
                sequence: 0,
                sig_op_count: 0,
            }],
            vec![
                TransactionOutput { value: 0, script_public_key: ScriptPublicKey::new(0, spk), payload: vec![] },
                TransactionOutput { value: 0, script_public_key: ScriptPublicKey::new(0, spk_other), payload: vec![] },
            ],
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            encoded_payload,
        );

        let populated_tx = PopulatedTransaction::new(
            &tx,
            vec![UtxoEntry {
                amount: 0,
                script_public_key: ScriptPublicKey::new(0, ScriptVec::from_slice(&[0x51])),
                block_daa_score: 0,
                is_coinbase: false,
                payload: Vec::new(),
            }],
        );

        let pov_daa_score = 100;
        assert_eq!(tv.check_transaction_payload(&populated_tx, pov_daa_score), Ok(()));
    }

    // =========================
    // Execution (action_id > 0) tests for validate_contract_state_rules
    // =========================

    #[test]
    fn test_execution_missing_state_input() {
        use core::str::FromStr;
        use cryptix_consensus_core::contract::ContractPayload;
        use cryptix_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
        use cryptix_consensus_core::tx::{scriptvec, ScriptPublicKey, ScriptVec, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry, PopulatedTransaction};
        use crate::params::MAINNET_PARAMS;
        use cryptix_txscript::pay_to_contract_script;

        let mut params = MAINNET_PARAMS.clone();
        params.non_coinbase_payload_activation_daa_score = 0;
        params.max_non_coinbase_payload_len = 40 * 1024;
        params.contracts_hardfork_daa_score = 100;

        let mut tv = TransactionValidator::new_for_tests(
            params.max_tx_inputs,
            params.max_tx_outputs,
            params.max_signature_script_len,
            params.max_script_public_key_len,
            params.ghostdag_k,
            params.coinbase_payload_script_public_key_max_len,
            params.coinbase_maturity,
            Default::default(),
        );
        tv.non_coinbase_payload_activation_daa_score = params.non_coinbase_payload_activation_daa_score;
        tv.max_non_coinbase_payload_len = params.max_non_coinbase_payload_len;
        tv.contracts_hardfork_daa_score = params.contracts_hardfork_daa_score;

        let prev_tx_id = TransactionId::from_str("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let cid = 7001u64;

        let payload = ContractPayload { v: 1, c: cid, a: 1, d: vec![0xAA] }.encode().unwrap();

        // No state input (input is OP_TRUE), but has a correct state output -> MissingContractState
        let spk_state = ScriptVec::from_slice(&pay_to_contract_script(cid));
        let tx = Transaction::new(
            0,
            vec![TransactionInput {
                previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id, index: 0 },
                signature_script: vec![],
                sequence: 0,
                sig_op_count: 0,
            }],
            vec![TransactionOutput { value: 0, script_public_key: ScriptPublicKey::new(0, spk_state), payload: vec![1, 2, 3] }],
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            payload,
        );

        let populated_tx = PopulatedTransaction::new(
            &tx,
            vec![UtxoEntry {
                amount: 100,
                script_public_key: ScriptPublicKey::new(0, scriptvec!(0x51)),
                block_daa_score: 0,
                is_coinbase: false,
                payload: Vec::new(),
            }],
        );

        let pov = 100;
        assert_match!(tv.validate_contract_state_rules(&populated_tx, pov), Err(TxRuleError::MissingContractState(_)));
    }

    #[test]
    fn test_execution_missing_state_output() {
        use core::str::FromStr;
        use cryptix_consensus_core::contract::ContractPayload;
        use cryptix_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
        use cryptix_consensus_core::tx::{ScriptPublicKey, ScriptVec, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry, PopulatedTransaction};
        use crate::params::MAINNET_PARAMS;
        use cryptix_txscript::pay_to_contract_script;

        let mut params = MAINNET_PARAMS.clone();
        params.non_coinbase_payload_activation_daa_score = 0;
        params.max_non_coinbase_payload_len = 40 * 1024;
        params.contracts_hardfork_daa_score = 100;

        let mut tv = TransactionValidator::new_for_tests(
            params.max_tx_inputs,
            params.max_tx_outputs,
            params.max_signature_script_len,
            params.max_script_public_key_len,
            params.ghostdag_k,
            params.coinbase_payload_script_public_key_max_len,
            params.coinbase_maturity,
            Default::default(),
        );
        tv.non_coinbase_payload_activation_daa_score = params.non_coinbase_payload_activation_daa_score;
        tv.max_non_coinbase_payload_len = params.max_non_coinbase_payload_len;
        tv.contracts_hardfork_daa_score = params.contracts_hardfork_daa_score;

        let prev_tx_id = TransactionId::from_str("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
        let cid = 7002u64;

        let payload = ContractPayload { v: 1, c: cid, a: 2, d: vec![] }.encode().unwrap();

        // Has a state input, but no state output
        let spk_state = ScriptVec::from_slice(&pay_to_contract_script(cid));
        let tx = Transaction::new(
            0,
            vec![TransactionInput {
                previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id, index: 0 },
                signature_script: vec![],
                sequence: 0,
                sig_op_count: 0,
            }],
            vec![TransactionOutput { value: 1, script_public_key: ScriptPublicKey::new(0, ScriptVec::from_slice(&[0x51])), payload: vec![] }],
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            payload,
        );
        let populated_tx = PopulatedTransaction::new(
            &tx,
            vec![UtxoEntry {
                amount: 0,
                script_public_key: ScriptPublicKey::new(0, spk_state),
                block_daa_score: 0,
                is_coinbase: false,
                payload: Vec::new(),
            }],
        );

        let pov = 100;
        assert_match!(tv.validate_contract_state_rules(&populated_tx, pov), Err(TxRuleError::MissingContractStateOutput));
    }

    #[test]
    fn test_execution_wrong_contract_id() {
        use core::str::FromStr;
        use cryptix_consensus_core::contract::ContractPayload;
        use cryptix_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
        use cryptix_consensus_core::tx::{ScriptPublicKey, ScriptVec, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry, PopulatedTransaction};
        use crate::params::MAINNET_PARAMS;
        use cryptix_txscript::pay_to_contract_script;

        let mut params = MAINNET_PARAMS.clone();
        params.non_coinbase_payload_activation_daa_score = 0;
        params.max_non_coinbase_payload_len = 40 * 1024;
        params.contracts_hardfork_daa_score = 100;

        let mut tv = TransactionValidator::new_for_tests(
            params.max_tx_inputs,
            params.max_tx_outputs,
            params.max_signature_script_len,
            params.max_script_public_key_len,
            params.ghostdag_k,
            params.coinbase_payload_script_public_key_max_len,
            params.coinbase_maturity,
            Default::default(),
        );
        tv.non_coinbase_payload_activation_daa_score = params.non_coinbase_payload_activation_daa_score;
        tv.max_non_coinbase_payload_len = params.max_non_coinbase_payload_len;
        tv.contracts_hardfork_daa_score = params.contracts_hardfork_daa_score;

        let prev_tx_id = TransactionId::from_str("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc").unwrap();
        let cid = 7003u64;
        let other_cid = 7999u64;

        let payload = ContractPayload { v: 1, c: cid, a: 3, d: vec![] }.encode().unwrap();

        let spk_state_in = ScriptVec::from_slice(&pay_to_contract_script(cid));
        let spk_state_out_wrong = ScriptVec::from_slice(&pay_to_contract_script(other_cid));

        let tx = Transaction::new(
            0,
            vec![TransactionInput {
                previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id, index: 0 },
                signature_script: vec![],
                sequence: 0,
                sig_op_count: 0,
            }],
            vec![TransactionOutput { value: 0, script_public_key: ScriptPublicKey::new(0, spk_state_out_wrong), payload: vec![] }],
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            payload,
        );
        let populated_tx = PopulatedTransaction::new(
            &tx,
            vec![UtxoEntry { amount: 0, script_public_key: ScriptPublicKey::new(0, spk_state_in), block_daa_score: 0, is_coinbase: false, payload: Vec::new() }],
        );

        let pov = 100;
        assert_match!(tv.validate_contract_state_rules(&populated_tx, pov), Err(TxRuleError::MissingContractStateOutput));
    }

    #[test]
    fn test_execution_state_too_large() {
        use core::str::FromStr;
        use cryptix_consensus_core::contract::{ContractPayload, MAX_CONTRACT_STATE_SIZE};
        use cryptix_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
        use cryptix_consensus_core::tx::{ScriptPublicKey, ScriptVec, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry, PopulatedTransaction};
        use crate::params::MAINNET_PARAMS;
        use cryptix_txscript::pay_to_contract_script;

        let mut params = MAINNET_PARAMS.clone();
        params.non_coinbase_payload_activation_daa_score = 0;
        params.max_non_coinbase_payload_len = 40 * 1024;
        params.contracts_hardfork_daa_score = 100;

        let mut tv = TransactionValidator::new_for_tests(
            params.max_tx_inputs,
            params.max_tx_outputs,
            params.max_signature_script_len,
            params.max_script_public_key_len,
            params.ghostdag_k,
            params.coinbase_payload_script_public_key_max_len,
            params.coinbase_maturity,
            Default::default(),
        );
        tv.non_coinbase_payload_activation_daa_score = params.non_coinbase_payload_activation_daa_score;
        tv.max_non_coinbase_payload_len = params.max_non_coinbase_payload_len;
        tv.contracts_hardfork_daa_score = params.contracts_hardfork_daa_score;

        let prev_tx_id = TransactionId::from_str("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd").unwrap();
        let cid = 7004u64;

        let payload = ContractPayload { v: 1, c: cid, a: 5, d: vec![] }.encode().unwrap();

        let spk_state = ScriptVec::from_slice(&pay_to_contract_script(cid));
        let too_large_state = vec![0u8; MAX_CONTRACT_STATE_SIZE + 1];

        let tx = Transaction::new(
            0,
            vec![TransactionInput {
                previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id, index: 0 },
                signature_script: vec![],
                sequence: 0,
                sig_op_count: 0,
            }],
            vec![TransactionOutput { value: 0, script_public_key: ScriptPublicKey::new(0, spk_state), payload: too_large_state }],
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            payload,
        );
        let populated_tx = PopulatedTransaction::new(
            &tx,
            vec![UtxoEntry { amount: 0, script_public_key: ScriptPublicKey::new(0, ScriptVec::from_slice(&pay_to_contract_script(cid))), block_daa_score: 0, is_coinbase: false, payload: Vec::new() }],
        );

        let pov = 100;
        assert_match!(tv.validate_contract_state_rules(&populated_tx, pov), Err(TxRuleError::StateTooLarge(_, _)));
    }

    #[test]
    fn test_execution_multiple_state_inputs() {
        use core::str::FromStr;
        use cryptix_consensus_core::contract::ContractPayload;
        use cryptix_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
        use cryptix_consensus_core::tx::{ScriptPublicKey, ScriptVec, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry, PopulatedTransaction};
        use crate::params::MAINNET_PARAMS;
        use cryptix_txscript::pay_to_contract_script;

        let mut params = MAINNET_PARAMS.clone();
        params.non_coinbase_payload_activation_daa_score = 0;
        params.max_non_coinbase_payload_len = 40 * 1024;
        params.contracts_hardfork_daa_score = 100;

        let mut tv = TransactionValidator::new_for_tests(
            params.max_tx_inputs,
            params.max_tx_outputs,
            params.max_signature_script_len,
            params.max_script_public_key_len,
            params.ghostdag_k,
            params.coinbase_payload_script_public_key_max_len,
            params.coinbase_maturity,
            Default::default(),
        );
        tv.non_coinbase_payload_activation_daa_score = params.non_coinbase_payload_activation_daa_score;
        tv.max_non_coinbase_payload_len = params.max_non_coinbase_payload_len;
        tv.contracts_hardfork_daa_score = params.contracts_hardfork_daa_score;

        let prev_tx_id = TransactionId::from_str("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee").unwrap();
        let cid = 7005u64;
        let payload = ContractPayload { v: 1, c: cid, a: 6, d: vec![] }.encode().unwrap();

        let spk_state = ScriptVec::from_slice(&pay_to_contract_script(cid));

        let tx = Transaction::new(
            0,
            vec![
                TransactionInput { previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id, index: 0 }, signature_script: vec![], sequence: 0, sig_op_count: 0 },
                TransactionInput { previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id, index: 1 }, signature_script: vec![], sequence: 0, sig_op_count: 0 },
            ],
            vec![TransactionOutput { value: 0, script_public_key: ScriptPublicKey::new(0, spk_state.clone()), payload: vec![] }],
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            payload,
        );

        let populated_tx = PopulatedTransaction::new(
            &tx,
            vec![
                UtxoEntry { amount: 0, script_public_key: ScriptPublicKey::new(0, spk_state.clone()), block_daa_score: 0, is_coinbase: false, payload: Vec::new() },
                UtxoEntry { amount: 0, script_public_key: ScriptPublicKey::new(0, spk_state), block_daa_score: 0, is_coinbase: false, payload: Vec::new() },
            ],
        );

        let pov = 100;
        assert_match!(tv.validate_contract_state_rules(&populated_tx, pov), Err(TxRuleError::MultipleStateUtxos(_)));
    }

    #[test]
    fn test_execution_multiple_state_outputs() {
        use core::str::FromStr;
        use cryptix_consensus_core::contract::ContractPayload;
        use cryptix_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
        use cryptix_consensus_core::tx::{ScriptPublicKey, ScriptVec, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry, PopulatedTransaction};
        use crate::params::MAINNET_PARAMS;
        use cryptix_txscript::pay_to_contract_script;

        let mut params = MAINNET_PARAMS.clone();
        params.non_coinbase_payload_activation_daa_score = 0;
        params.max_non_coinbase_payload_len = 40 * 1024;
        params.contracts_hardfork_daa_score = 100;

        let mut tv = TransactionValidator::new_for_tests(
            params.max_tx_inputs,
            params.max_tx_outputs,
            params.max_signature_script_len,
            params.max_script_public_key_len,
            params.ghostdag_k,
            params.coinbase_payload_script_public_key_max_len,
            params.coinbase_maturity,
            Default::default(),
        );
        tv.non_coinbase_payload_activation_daa_score = params.non_coinbase_payload_activation_daa_score;
        tv.max_non_coinbase_payload_len = params.max_non_coinbase_payload_len;
        tv.contracts_hardfork_daa_score = params.contracts_hardfork_daa_score;

        let prev_tx_id = TransactionId::from_str("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
        let cid = 7006u64;
        let payload = ContractPayload { v: 1, c: cid, a: 7, d: vec![] }.encode().unwrap();

        let spk_state = ScriptVec::from_slice(&pay_to_contract_script(cid));

        let tx = Transaction::new(
            0,
            vec![TransactionInput {
                previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id, index: 0 },
                signature_script: vec![],
                sequence: 0,
                sig_op_count: 0,
            }],
            vec![
                TransactionOutput { value: 0, script_public_key: ScriptPublicKey::new(0, spk_state.clone()), payload: vec![0x01] },
                TransactionOutput { value: 0, script_public_key: ScriptPublicKey::new(0, spk_state.clone()), payload: vec![0x02] },
            ],
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            payload,
        );

        let populated_tx = PopulatedTransaction::new(
            &tx,
            vec![UtxoEntry {
                amount: 0,
                script_public_key: ScriptPublicKey::new(0, spk_state),
                block_daa_score: 0,
                is_coinbase: false,
                payload: Vec::new(),
            }],
        );

        let pov = 100;
        assert_match!(tv.validate_contract_state_rules(&populated_tx, pov), Err(TxRuleError::MultipleStateUtxos(_)));
    }

    #[test]
    fn test_execution_valid() {
        use core::str::FromStr;
        use cryptix_consensus_core::contract::ContractPayload;
        use cryptix_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
        use cryptix_consensus_core::tx::{ScriptPublicKey, ScriptVec, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry, PopulatedTransaction};
        use crate::params::MAINNET_PARAMS;
        use cryptix_txscript::pay_to_contract_script;

        let mut params = MAINNET_PARAMS.clone();
        params.non_coinbase_payload_activation_daa_score = 0;
        params.max_non_coinbase_payload_len = 40 * 1024;
        params.contracts_hardfork_daa_score = 100;

        let mut tv = TransactionValidator::new_for_tests(
            params.max_tx_inputs,
            params.max_tx_outputs,
            params.max_signature_script_len,
            params.max_script_public_key_len,
            params.ghostdag_k,
            params.coinbase_payload_script_public_key_max_len,
            params.coinbase_maturity,
            Default::default(),
        );
        tv.non_coinbase_payload_activation_daa_score = params.non_coinbase_payload_activation_daa_score;
        tv.max_non_coinbase_payload_len = params.max_non_coinbase_payload_len;
        tv.contracts_hardfork_daa_score = params.contracts_hardfork_daa_score;

        let prev_tx_id = TransactionId::from_str("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").unwrap();
        let cid = 7007u64;

        let payload = ContractPayload { v: 1, c: cid, a: 2, d: vec![0xAB] }.encode().unwrap();

        let spk_state = ScriptVec::from_slice(&pay_to_contract_script(cid));
        let new_state = vec![1, 2, 3, 4];

        let tx = Transaction::new(
            0,
            vec![TransactionInput {
                previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id, index: 0 },
                signature_script: vec![],
                sequence: 0,
                sig_op_count: 0,
            }],
            vec![TransactionOutput { value: 0, script_public_key: ScriptPublicKey::new(0, spk_state.clone()), payload: new_state }],
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            payload,
        );

        let populated_tx = PopulatedTransaction::new(
            &tx,
            vec![UtxoEntry {
                amount: 0,
                script_public_key: ScriptPublicKey::new(0, spk_state),
                block_daa_score: 0,
                is_coinbase: false,
                payload: Vec::new(),
            }],
        );

        let pov = 100;
        assert_eq!(tv.validate_contract_state_rules(&populated_tx, pov), Ok(()));
    }
}
