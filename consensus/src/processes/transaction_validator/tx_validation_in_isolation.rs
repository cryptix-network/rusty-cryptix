use crate::constants::{MAX_SOMPI, TX_VERSION};
use cryptix_consensus_core::tx::Transaction;
use std::collections::HashSet;

use super::{
    errors::{TxResult, TxRuleError},
    transaction_validator_populated::parse_atomic_payload,
    TransactionValidator,
};

impl TransactionValidator {
    pub fn validate_tx_in_isolation(&self, tx: &Transaction, pov_daa_score: u64) -> TxResult<()> {
        let payload_hf_activated = pov_daa_score >= self.payload_hf_activation_daa_score;
        self.check_transaction_inputs_in_isolation(tx)?;
        self.check_transaction_outputs_in_isolation(tx)?;
        self.check_coinbase_in_isolation(tx)?;

        check_transaction_output_value_ranges(tx)?;
        check_duplicate_transaction_inputs(tx)?;
        check_gas(tx)?;
        check_transaction_subnetwork(tx, payload_hf_activated)?;
        check_transaction_payload(tx, payload_hf_activated, self.payload_max_len_consensus)?;
        check_transaction_version(tx)
    }

    fn check_transaction_inputs_in_isolation(&self, tx: &Transaction) -> TxResult<()> {
        self.check_transaction_inputs_count(tx)?;
        self.check_transaction_signature_scripts(tx)
    }

    fn check_transaction_outputs_in_isolation(&self, tx: &Transaction) -> TxResult<()> {
        self.check_transaction_outputs_count(tx)?;
        self.check_transaction_script_public_keys(tx)
    }

    fn check_coinbase_in_isolation(&self, tx: &cryptix_consensus_core::tx::Transaction) -> TxResult<()> {
        if !tx.is_coinbase() {
            return Ok(());
        }
        if !tx.inputs.is_empty() {
            return Err(TxRuleError::CoinbaseHasInputs(tx.inputs.len()));
        }
        let outputs_limit = self.ghostdag_k as u64 + 2;
        if tx.outputs.len() as u64 > outputs_limit {
            return Err(TxRuleError::CoinbaseTooManyOutputs(tx.outputs.len(), outputs_limit));
        }
        for (i, output) in tx.outputs.iter().enumerate() {
            if output.script_public_key.script().len() > self.coinbase_payload_script_public_key_max_len as usize {
                return Err(TxRuleError::CoinbaseScriptPublicKeyTooLong(i));
            }
        }
        Ok(())
    }

    fn check_transaction_outputs_count(&self, tx: &Transaction) -> TxResult<()> {
        if tx.outputs.len() > self.max_tx_outputs {
            return Err(TxRuleError::TooManyOutputs(tx.inputs.len(), self.max_tx_inputs));
        }

        Ok(())
    }

    fn check_transaction_inputs_count(&self, tx: &Transaction) -> TxResult<()> {
        if !tx.is_coinbase() && tx.inputs.is_empty() {
            return Err(TxRuleError::NoTxInputs);
        }

        if tx.inputs.len() > self.max_tx_inputs {
            return Err(TxRuleError::TooManyInputs(tx.inputs.len(), self.max_tx_inputs));
        }

        Ok(())
    }

    // The main purpose of this check is to avoid overflows when calculating transaction mass later.
    fn check_transaction_signature_scripts(&self, tx: &Transaction) -> TxResult<()> {
        if let Some(i) = tx.inputs.iter().position(|input| input.signature_script.len() > self.max_signature_script_len) {
            return Err(TxRuleError::TooBigSignatureScript(i, self.max_signature_script_len));
        }

        Ok(())
    }

    // The main purpose of this check is to avoid overflows when calculating transaction mass later.
    fn check_transaction_script_public_keys(&self, tx: &Transaction) -> TxResult<()> {
        if let Some(i) = tx.outputs.iter().position(|input| input.script_public_key.script().len() > self.max_script_public_key_len) {
            return Err(TxRuleError::TooBigScriptPublicKey(i, self.max_script_public_key_len));
        }

        Ok(())
    }
}

fn check_duplicate_transaction_inputs(tx: &Transaction) -> TxResult<()> {
    let mut existing = HashSet::new();
    for input in &tx.inputs {
        if !existing.insert(input.previous_outpoint) {
            return Err(TxRuleError::TxDuplicateInputs);
        }
    }
    Ok(())
}

fn check_gas(tx: &Transaction) -> TxResult<()> {
    // This should be revised if subnetworks are activated (along with other validations that weren't copied from cryptixd)
    if tx.gas > 0 {
        return Err(TxRuleError::TxHasGas);
    }
    Ok(())
}

fn check_transaction_payload(tx: &Transaction, payload_hf_activated: bool, payload_max_len_consensus: usize) -> TxResult<()> {
    if tx.is_coinbase() {
        return Ok(());
    }

    if !payload_hf_activated {
        if !tx.payload.is_empty() {
            return Err(TxRuleError::NonCoinbaseTxHasPayload);
        }
        return Ok(());
    }

    if tx.subnetwork_id.is_payload() {
        let payload_len = tx.payload.len();
        if payload_len == 0 {
            return Err(TxRuleError::PayloadSubnetworkHasNoPayload);
        }
        if payload_len > payload_max_len_consensus {
            return Err(TxRuleError::PayloadLengthAboveMax(payload_len, payload_max_len_consensus));
        }
        validate_atomic_payload_shape(tx).map_err(TxRuleError::InvalidAtomicPayload)?;
        return Ok(());
    }

    if !tx.payload.is_empty() {
        return Err(TxRuleError::PayloadInInvalidSubnetwork(tx.subnetwork_id.clone()));
    }
    Ok(())
}

fn validate_atomic_payload_shape(tx: &Transaction) -> Result<(), String> {
    let Some(parsed_payload) = parse_atomic_payload(tx.payload.as_slice())? else {
        return Ok(());
    };
    if parsed_payload.auth_input_index as usize >= tx.inputs.len() {
        return Err(format!(
            "auth_input_index `{}` is out of range for {} tx input(s)",
            parsed_payload.auth_input_index,
            tx.inputs.len()
        ));
    }
    Ok(())
}

fn check_transaction_version(tx: &Transaction) -> TxResult<()> {
    if tx.version != TX_VERSION {
        return Err(TxRuleError::UnknownTxVersion(tx.version));
    }
    Ok(())
}

fn check_transaction_output_value_ranges(tx: &Transaction) -> TxResult<()> {
    let mut total: u64 = 0;
    for (i, output) in tx.outputs.iter().enumerate() {
        if output.value == 0 {
            return Err(TxRuleError::TxOutZero(i));
        }

        if output.value > MAX_SOMPI {
            return Err(TxRuleError::TxOutTooHigh(i));
        }

        if let Some(new_total) = total.checked_add(output.value) {
            total = new_total
        } else {
            return Err(TxRuleError::OutputsValueOverflow);
        }

        if total > MAX_SOMPI {
            return Err(TxRuleError::TotalTxOutTooHigh);
        }
    }

    Ok(())
}

fn check_transaction_subnetwork(tx: &Transaction, payload_hf_activated: bool) -> TxResult<()> {
    if !payload_hf_activated {
        if tx.is_coinbase() || tx.subnetwork_id.is_native() {
            return Ok(());
        }
        return Err(TxRuleError::SubnetworksDisabled(tx.subnetwork_id.clone()));
    }

    if tx.subnetwork_id == cryptix_consensus_core::subnets::SUBNETWORK_ID_COINBASE
        || tx.subnetwork_id == cryptix_consensus_core::subnets::SUBNETWORK_ID_NATIVE
        || tx.subnetwork_id == cryptix_consensus_core::subnets::SUBNETWORK_ID_PAYLOAD
    {
        Ok(())
    } else {
        Err(TxRuleError::SubnetworksDisabled(tx.subnetwork_id.clone()))
    }
}

#[cfg(test)]
mod tests {
    use cryptix_consensus_core::{
        subnets::{SubnetworkId, SUBNETWORK_ID_COINBASE, SUBNETWORK_ID_NATIVE, SUBNETWORK_ID_PAYLOAD},
        tx::{scriptvec, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput},
    };
    use cryptix_core::assert_match;

    use crate::{
        constants::TX_VERSION,
        params::MAINNET_PARAMS,
        processes::transaction_validator::{errors::TxRuleError, TransactionValidator},
    };

    #[test]
    fn validate_tx_in_isolation_test() {
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

        let valid_cb = Transaction::new(
            0,
            vec![],
            vec![TransactionOutput {
                value: 0x12a05f200,
                script_public_key: ScriptPublicKey::new(
                    0,
                    scriptvec!(
                        0xa9, 0x14, 0xda, 0x17, 0x45, 0xe9, 0xb5, 0x49, 0xbd, 0x0b, 0xfa, 0x1a, 0x56, 0x99, 0x71, 0xc7, 0x7e, 0xba,
                        0x30, 0xcd, 0x5a, 0x4b, 0x87
                    ),
                ),
            }],
            0,
            SUBNETWORK_ID_COINBASE,
            0,
            vec![9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );

        tv.validate_tx_in_isolation(&valid_cb, 0).unwrap();

        let valid_tx = Transaction::new(
            0,
            vec![TransactionInput {
                previous_outpoint: TransactionOutpoint {
                    transaction_id: TransactionId::from_slice(&[
                        0x03, 0x2e, 0x38, 0xe9, 0xc0, 0xa8, 0x4c, 0x60, 0x46, 0xd6, 0x87, 0xd1, 0x05, 0x56, 0xdc, 0xac, 0xc4, 0x1d,
                        0x27, 0x5e, 0xc5, 0x5f, 0xc0, 0x07, 0x79, 0xac, 0x88, 0xfd, 0xf3, 0x57, 0xa1, 0x87,
                    ]),
                    index: 0,
                },
                signature_script: vec![
                    0x49, // OP_DATA_73
                    0x30, 0x46, 0x02, 0x21, 0x00, 0xc3, 0x52, 0xd3, 0xdd, 0x99, 0x3a, 0x98, 0x1b, 0xeb, 0xa4, 0xa6, 0x3a, 0xd1, 0x5c,
                    0x20, 0x92, 0x75, 0xca, 0x94, 0x70, 0xab, 0xfc, 0xd5, 0x7d, 0xa9, 0x3b, 0x58, 0xe4, 0xeb, 0x5d, 0xce, 0x82, 0x02,
                    0x21, 0x00, 0x84, 0x07, 0x92, 0xbc, 0x1f, 0x45, 0x60, 0x62, 0x81, 0x9f, 0x15, 0xd3, 0x3e, 0xe7, 0x05, 0x5c, 0xf7,
                    0xb5, 0xee, 0x1a, 0xf1, 0xeb, 0xcc, 0x60, 0x28, 0xd9, 0xcd, 0xb1, 0xc3, 0xaf, 0x77, 0x48,
                    0x01, // 73-byte signature
                    0x41, // OP_DATA_65
                    0x04, 0xf4, 0x6d, 0xb5, 0xe9, 0xd6, 0x1a, 0x9d, 0xc2, 0x7b, 0x8d, 0x64, 0xad, 0x23, 0xe7, 0x38, 0x3a, 0x4e, 0x6c,
                    0xa1, 0x64, 0x59, 0x3c, 0x25, 0x27, 0xc0, 0x38, 0xc0, 0x85, 0x7e, 0xb6, 0x7e, 0xe8, 0xe8, 0x25, 0xdc, 0xa6, 0x50,
                    0x46, 0xb8, 0x2c, 0x93, 0x31, 0x58, 0x6c, 0x82, 0xe0, 0xfd, 0x1f, 0x63, 0x3f, 0x25, 0xf8, 0x7c, 0x16, 0x1b, 0xc6,
                    0xf8, 0xa6, 0x30, 0x12, 0x1d, 0xf2, 0xb3, 0xd3, // 65-byte pubkey
                ],
                sequence: u64::MAX,
                sig_op_count: 0,
            }],
            vec![
                TransactionOutput {
                    value: 0x2123e300,
                    script_public_key: ScriptPublicKey::new(
                        0,
                        scriptvec!(
                            0x76, // OP_DUP
                            0xa9, // OP_HASH160
                            0x14, // OP_DATA_20
                            0xc3, 0x98, 0xef, 0xa9, 0xc3, 0x92, 0xba, 0x60, 0x13, 0xc5, 0xe0, 0x4e, 0xe7, 0x29, 0x75, 0x5e, 0xf7,
                            0xf5, 0x8b, 0x32, 0x88, // OP_EQUALVERIFY
                            0xac  // OP_CHECKSIG
                        ),
                    ),
                },
                TransactionOutput {
                    value: 0x108e20f00,
                    script_public_key: ScriptPublicKey::new(
                        0,
                        scriptvec!(
                            0x76, // OP_DUP
                            0xa9, // OP_HASH160
                            0x14, // OP_DATA_20
                            0x94, 0x8c, 0x76, 0x5a, 0x69, 0x14, 0xd4, 0x3f, 0x2a, 0x7a, 0xc1, 0x77, 0xda, 0x2c, 0x2f, 0x6b, 0x52,
                            0xde, 0x3d, 0x7c, 0x88, // OP_EQUALVERIFY
                            0xac  // OP_CHECKSIG
                        ),
                    ),
                },
            ],
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            vec![],
        );

        tv.validate_tx_in_isolation(&valid_tx, 0).unwrap();

        let mut tx: Transaction = valid_tx.clone();
        tx.subnetwork_id = SubnetworkId::from_byte(3);
        assert_match!(tv.validate_tx_in_isolation(&tx, 0), Err(TxRuleError::SubnetworksDisabled(_)));

        let mut tx = valid_tx.clone();
        tx.inputs = vec![];
        assert_match!(tv.validate_tx_in_isolation(&tx, 0), Err(TxRuleError::NoTxInputs));

        let mut tx = valid_tx.clone();
        tx.inputs = (0..params.max_tx_inputs + 1).map(|_| valid_tx.inputs[0].clone()).collect();
        assert_match!(tv.validate_tx_in_isolation(&tx, 0), Err(TxRuleError::TooManyInputs(_, _)));

        let mut tx = valid_tx.clone();
        tx.inputs[0].signature_script = vec![0; params.max_signature_script_len + 1];
        assert_match!(tv.validate_tx_in_isolation(&tx, 0), Err(TxRuleError::TooBigSignatureScript(_, _)));

        let mut tx = valid_tx.clone();
        tx.outputs = (0..params.max_tx_outputs + 1).map(|_| valid_tx.outputs[0].clone()).collect();
        assert_match!(tv.validate_tx_in_isolation(&tx, 0), Err(TxRuleError::TooManyOutputs(_, _)));

        let mut tx = valid_tx.clone();
        tx.outputs[0].script_public_key = ScriptPublicKey::new(0, scriptvec![0u8; params.max_script_public_key_len + 1]);
        assert_match!(tv.validate_tx_in_isolation(&tx, 0), Err(TxRuleError::TooBigScriptPublicKey(_, _)));

        let mut tx = valid_tx.clone();
        tx.inputs.push(tx.inputs[0].clone());
        assert_match!(tv.validate_tx_in_isolation(&tx, 0), Err(TxRuleError::TxDuplicateInputs));

        let mut tx = valid_tx.clone();
        tx.gas = 1;
        assert_match!(tv.validate_tx_in_isolation(&tx, 0), Err(TxRuleError::TxHasGas));

        let mut tx = valid_tx.clone();
        tx.payload = vec![0];
        assert_match!(tv.validate_tx_in_isolation(&tx, 0), Err(TxRuleError::NonCoinbaseTxHasPayload));

        let mut tx = valid_tx.clone();
        tx.version = TX_VERSION + 1;
        assert_match!(tv.validate_tx_in_isolation(&tx, 0), Err(TxRuleError::UnknownTxVersion(_)));

        let tv_post_hf = TransactionValidator::new(
            params.max_tx_inputs,
            params.max_tx_outputs,
            params.max_signature_script_len,
            params.max_script_public_key_len,
            params.ghostdag_k,
            params.coinbase_payload_script_public_key_max_len,
            params.coinbase_maturity,
            Default::default(),
            cryptix_consensus_core::mass::MassCalculator::new(0, 0, 0, 0, 1),
            params.storage_mass_activation_daa_score,
            0,
            8192,
        );

        let mut tx = valid_tx.clone();
        tx.subnetwork_id = SUBNETWORK_ID_PAYLOAD;
        tx.payload = vec![1];
        tv_post_hf.validate_tx_in_isolation(&tx, 0).unwrap();

        tx.payload = vec![];
        assert_match!(tv_post_hf.validate_tx_in_isolation(&tx, 0), Err(TxRuleError::PayloadSubnetworkHasNoPayload));

        tx.payload = vec![7; 8193];
        assert_match!(tv_post_hf.validate_tx_in_isolation(&tx, 0), Err(TxRuleError::PayloadLengthAboveMax(8193, 8192)));

        let mut tx = valid_tx.clone();
        tx.payload = vec![2];
        assert_match!(tv_post_hf.validate_tx_in_isolation(&tx, 0), Err(TxRuleError::PayloadInInvalidSubnetwork(_)));

        let mut tx = valid_tx;
        tx.subnetwork_id = SubnetworkId::from_byte(10);
        assert_match!(tv_post_hf.validate_tx_in_isolation(&tx, 0), Err(TxRuleError::SubnetworksDisabled(_)));

        let mut tx = Transaction::new(
            0,
            vec![TransactionInput {
                previous_outpoint: TransactionOutpoint {
                    transaction_id: TransactionId::from_slice(&[
                        0x13, 0x2e, 0x38, 0xe9, 0xc0, 0xa8, 0x4c, 0x60, 0x46, 0xd6, 0x87, 0xd1, 0x05, 0x56, 0xdc, 0xac, 0xc4, 0x1d,
                        0x27, 0x5e, 0xc5, 0x5f, 0xc0, 0x07, 0x79, 0xac, 0x88, 0xfd, 0xf3, 0x57, 0xa1, 0x88,
                    ]),
                    index: 0,
                },
                signature_script: vec![0x51],
                sequence: u64::MAX,
                sig_op_count: 0,
            }],
            vec![TransactionOutput {
                value: 0x108e20f00,
                script_public_key: ScriptPublicKey::new(
                    0,
                    scriptvec!(
                        0x76, // OP_DUP
                        0xa9, // OP_HASH160
                        0x14, // OP_DATA_20
                        0x94, 0x8c, 0x76, 0x5a, 0x69, 0x14, 0xd4, 0x3f, 0x2a, 0x7a, 0xc1, 0x77, 0xda, 0x2c, 0x2f, 0x6b, 0x52, 0xde,
                        0x3d, 0x7c, 0x88, // OP_EQUALVERIFY
                        0xac  // OP_CHECKSIG
                    ),
                ),
            }],
            0,
            SUBNETWORK_ID_PAYLOAD,
            0,
            vec![],
        );

        let mut valid_cat_transfer_payload = Vec::new();
        valid_cat_transfer_payload.extend_from_slice(b"CAT");
        valid_cat_transfer_payload.push(1); // version
        valid_cat_transfer_payload.push(1); // Transfer
        valid_cat_transfer_payload.push(0); // flags
        valid_cat_transfer_payload.extend_from_slice(&0u16.to_le_bytes()); // auth_input_index
        valid_cat_transfer_payload.extend_from_slice(&1u64.to_le_bytes()); // nonce
        valid_cat_transfer_payload.extend_from_slice(&[5u8; 32]); // asset_id
        valid_cat_transfer_payload.extend_from_slice(&[7u8; 32]); // to_owner_id
        valid_cat_transfer_payload.extend_from_slice(&1u128.to_le_bytes()); // amount

        tx.payload = valid_cat_transfer_payload.clone();
        tv_post_hf.validate_tx_in_isolation(&tx, 0).unwrap();

        let mut bad_auth_index_payload = valid_cat_transfer_payload.clone();
        let bad_auth_index_bytes = 1u16.to_le_bytes();
        bad_auth_index_payload[6] = bad_auth_index_bytes[0];
        bad_auth_index_payload[7] = bad_auth_index_bytes[1];
        tx.payload = bad_auth_index_payload;
        assert_match!(tv_post_hf.validate_tx_in_isolation(&tx, 0), Err(TxRuleError::InvalidAtomicPayload(_)));

        let mut bad_version_payload = valid_cat_transfer_payload.clone();
        bad_version_payload[3] = 2;
        tx.payload = bad_version_payload;
        assert_match!(tv_post_hf.validate_tx_in_isolation(&tx, 0), Err(TxRuleError::InvalidAtomicPayload(_)));

        let mut bad_nonce_payload = valid_cat_transfer_payload.clone();
        bad_nonce_payload[8..16].copy_from_slice(&0u64.to_le_bytes());
        tx.payload = bad_nonce_payload;
        assert_match!(tv_post_hf.validate_tx_in_isolation(&tx, 0), Err(TxRuleError::InvalidAtomicPayload(_)));

        let mut bad_create_payload = Vec::new();
        bad_create_payload.extend_from_slice(b"CAT");
        bad_create_payload.push(1); // version
        bad_create_payload.push(0); // CreateAsset
        bad_create_payload.push(0); // flags
        bad_create_payload.extend_from_slice(&0u16.to_le_bytes()); // auth_input_index
        bad_create_payload.extend_from_slice(&2u64.to_le_bytes()); // nonce
        bad_create_payload.push(8); // decimals
        bad_create_payload.push(1); // Capped
        bad_create_payload.extend_from_slice(&0u128.to_le_bytes()); // invalid max_supply for capped assets
        bad_create_payload.extend_from_slice(&[9u8; 32]); // mint_authority_owner_id
        bad_create_payload.push(4); // name len
        bad_create_payload.push(3); // symbol len
        bad_create_payload.extend_from_slice(&5u16.to_le_bytes()); // metadata len
        bad_create_payload.extend_from_slice(b"Gold");
        bad_create_payload.extend_from_slice(b"GLD");
        bad_create_payload.extend_from_slice(b"hello");
        tx.payload = bad_create_payload;
        assert_match!(tv_post_hf.validate_tx_in_isolation(&tx, 0), Err(TxRuleError::InvalidAtomicPayload(_)));
    }
}
