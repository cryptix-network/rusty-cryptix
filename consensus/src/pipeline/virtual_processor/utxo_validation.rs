use super::VirtualStateProcessor;
use crate::{
    errors::{
        BlockProcessResult,
        RuleError::{BadAcceptedIDMerkleRoot, BadCoinbaseTransaction, BadUTXOCommitment, InvalidTransactionsInUtxoContext},
    },
    model::stores::{block_transactions::BlockTransactionsStoreReader, daa::DaaStoreReader, ghostdag::GhostdagData},
    processes::transaction_validator::{
        errors::{TxResult, TxRuleError},
        transaction_validator_populated::TxValidationFlags,
    },
};
use cryptix_consensus_core::{
    acceptance_data::{AcceptedTxEntry, MergesetBlockAcceptanceData},
    api::args::TransactionValidationArgs,
    coinbase::*,
    hashing,
    header::Header,
    mass::Kip9Version,
    muhash::MuHashExtensions,
    tx::{MutableTransaction, PopulatedTransaction, Transaction, TransactionId, ValidatedTransaction, VerifiableTransaction},
    utxo::{
        utxo_diff::UtxoDiff,
        utxo_view::{UtxoView, UtxoViewComposition},
    },
    BlockHashMap, BlockHashSet, HashMapCustomHasher,
};
use cryptix_core::{info, trace};
use cryptix_hashes::Hash;
use cryptix_muhash::MuHash;
use cryptix_utils::refs::Refs;

use rayon::prelude::*;
use std::{iter::once, ops::Deref};

/// A context for processing the UTXO state of a block with respect to its selected parent.
/// Note this can also be the virtual block.
pub(super) struct UtxoProcessingContext<'a> {
    pub ghostdag_data: Refs<'a, GhostdagData>,
    pub multiset_hash: MuHash,
    pub mergeset_diff: UtxoDiff,
    pub accepted_tx_ids: Vec<TransactionId>,
    pub mergeset_acceptance_data: Vec<MergesetBlockAcceptanceData>,
    pub mergeset_rewards: BlockHashMap<BlockRewardData>,
}

impl<'a> UtxoProcessingContext<'a> {
    pub fn new(ghostdag_data: Refs<'a, GhostdagData>, selected_parent_multiset_hash: MuHash) -> Self {
        let mergeset_size = ghostdag_data.mergeset_size();
        Self {
            ghostdag_data,
            multiset_hash: selected_parent_multiset_hash,
            mergeset_diff: UtxoDiff::default(),
            accepted_tx_ids: Vec::with_capacity(1), // We expect at least the selected parent coinbase tx
            mergeset_rewards: BlockHashMap::with_capacity(mergeset_size),
            mergeset_acceptance_data: Vec::with_capacity(mergeset_size),
        }
    }

    pub fn selected_parent(&self) -> Hash {
        self.ghostdag_data.selected_parent
    }
}

impl VirtualStateProcessor {
    /// Calculates UTXO state and transaction acceptance data relative to the selected parent state
    pub(super) fn calculate_utxo_state<V: UtxoView + Sync>(
        &self,
        ctx: &mut UtxoProcessingContext,
        selected_parent_utxo_view: &V,
        pov_daa_score: u64,
    ) {
        let selected_parent_transactions = self.block_transactions_store.get(ctx.selected_parent()).unwrap();
        let validated_coinbase = ValidatedTransaction::new_coinbase(&selected_parent_transactions[0]);

        ctx.mergeset_diff.add_transaction(&validated_coinbase, pov_daa_score).unwrap();
        ctx.multiset_hash.add_transaction(&validated_coinbase, pov_daa_score);
        let validated_coinbase_id = validated_coinbase.id();
        ctx.accepted_tx_ids.push(validated_coinbase_id);

        for (i, (merged_block, txs)) in once((ctx.selected_parent(), selected_parent_transactions))
            .chain(
                ctx.ghostdag_data
                    .consensus_ordered_mergeset_without_selected_parent(self.ghostdag_primary_store.deref())
                    .map(|b| (b, self.block_transactions_store.get(b).unwrap())),
            )
            .enumerate()
        {
            // Create a composed UTXO view from the selected parent UTXO view + the mergeset UTXO diff
            let composed_view = selected_parent_utxo_view.compose(&ctx.mergeset_diff);

            // The first block in the mergeset is always the selected parent
            let is_selected_parent = i == 0;

            // No need to fully validate selected parent transactions since selected parent txs were already validated
            // as part of selected parent UTXO state verification with the exact same UTXO context.
            let validation_flags = if is_selected_parent { TxValidationFlags::SkipScriptChecks } else { TxValidationFlags::Full };
            let validated_transactions = self.validate_transactions_in_parallel(&txs, &composed_view, pov_daa_score, validation_flags);

            let mut block_fee = 0u64;
            for (validated_tx, _) in validated_transactions.iter() {
                ctx.mergeset_diff.add_transaction(validated_tx, pov_daa_score).unwrap();
                ctx.multiset_hash.add_transaction(validated_tx, pov_daa_score);
                ctx.accepted_tx_ids.push(validated_tx.id());
                block_fee += validated_tx.calculated_fee;
            }

            if is_selected_parent {
                // For the selected parent, we prepend the coinbase tx
                ctx.mergeset_acceptance_data.push(MergesetBlockAcceptanceData {
                    block_hash: merged_block,
                    accepted_transactions: once(AcceptedTxEntry { transaction_id: validated_coinbase_id, index_within_block: 0 })
                        .chain(
                            validated_transactions
                                .into_iter()
                                .map(|(tx, tx_idx)| AcceptedTxEntry { transaction_id: tx.id(), index_within_block: tx_idx }),
                        )
                        .collect(),
                });
            } else {
                ctx.mergeset_acceptance_data.push(MergesetBlockAcceptanceData {
                    block_hash: merged_block,
                    accepted_transactions: validated_transactions
                        .into_iter()
                        .map(|(tx, tx_idx)| AcceptedTxEntry { transaction_id: tx.id(), index_within_block: tx_idx })
                        .collect(),
                });
            }

            let coinbase_data = self.coinbase_manager.deserialize_coinbase_payload(&txs[0].payload).unwrap();
            ctx.mergeset_rewards.insert(
                merged_block,
                BlockRewardData::new(coinbase_data.subsidy, block_fee, coinbase_data.miner_data.script_public_key),
            );
        }

        // Make sure accepted tx ids are sorted before building the merkle root
        // NOTE: when subnetworks will be enabled, the sort should consider them in order to allow grouping under a merkle subtree
        ctx.accepted_tx_ids.sort();
    }

    /// Verify that the current block fully respects its own UTXO view. We define a block as
    /// UTXO valid if all the following conditions hold:
    ///     1. The block header includes the expected `utxo_commitment`.
    ///     2. The block header includes the expected `accepted_id_merkle_root`.
    ///     3. The block coinbase transaction rewards the mergeset blocks correctly.
    ///     4. All non-coinbase block transactions are valid against its own UTXO view.
    pub(super) fn verify_expected_utxo_state<V: UtxoView + Sync>(
        &self,
        ctx: &mut UtxoProcessingContext,
        selected_parent_utxo_view: &V,
        header: &Header,
    ) -> BlockProcessResult<()> {
        // Verify header UTXO commitment
        let expected_commitment = ctx.multiset_hash.finalize();
        if expected_commitment != header.utxo_commitment {
            return Err(BadUTXOCommitment(header.hash, header.utxo_commitment, expected_commitment));
        }
        trace!("correct commitment: {}, {}", header.hash, expected_commitment);

        // Verify header accepted_id_merkle_root
        let expected_accepted_id_merkle_root = cryptix_merkle::calc_merkle_root(ctx.accepted_tx_ids.iter().copied());
        if expected_accepted_id_merkle_root != header.accepted_id_merkle_root {
            return Err(BadAcceptedIDMerkleRoot(header.hash, header.accepted_id_merkle_root, expected_accepted_id_merkle_root));
        }

        let txs = self.block_transactions_store.get(header.hash).unwrap();

        // Verify coinbase transaction
        self.verify_coinbase_transaction(
            &txs[0],
            header.daa_score,
            &ctx.ghostdag_data,
            &ctx.mergeset_rewards,
            &self.daa_excluded_store.get_mergeset_non_daa(header.hash).unwrap(),
        )?;

        // Verify all transactions are valid in context
        let current_utxo_view = selected_parent_utxo_view.compose(&ctx.mergeset_diff);
        let validated_transactions =
            self.validate_transactions_in_parallel(&txs, &current_utxo_view, header.daa_score, TxValidationFlags::Full);
        if validated_transactions.len() < txs.len() - 1 {
            // Some non-coinbase transactions are invalid
            return Err(InvalidTransactionsInUtxoContext(txs.len() - 1 - validated_transactions.len(), txs.len() - 1));
        }

        Ok(())
    }

    fn verify_coinbase_transaction(
        &self,
        coinbase: &Transaction,
        daa_score: u64,
        ghostdag_data: &GhostdagData,
        mergeset_rewards: &BlockHashMap<BlockRewardData>,
        mergeset_non_daa: &BlockHashSet,
    ) -> BlockProcessResult<()> {
        // Extract only miner data from the provided coinbase
        let miner_data = self.coinbase_manager.deserialize_coinbase_payload(&coinbase.payload).unwrap().miner_data;
        let expected_coinbase = self
            .coinbase_manager
            .expected_coinbase_transaction(daa_score, miner_data, ghostdag_data, mergeset_rewards, mergeset_non_daa)
            .unwrap()
            .tx;
        if hashing::tx::hash(coinbase, false) != hashing::tx::hash(&expected_coinbase, false) {
            Err(BadCoinbaseTransaction)
        } else {
            Ok(())
        }
    }

    /// Validates transactions against the provided `utxo_view` and returns a vector with all transactions
    /// which passed the validation along with their original index within the containing block
    pub(crate) fn validate_transactions_in_parallel<'a, V: UtxoView + Sync>(
        &self,
        txs: &'a Vec<Transaction>,
        utxo_view: &V,
        pov_daa_score: u64,
        flags: TxValidationFlags,
    ) -> Vec<(ValidatedTransaction<'a>, u32)> {

        self.thread_pool.install(|| {
            txs
                .par_iter() // All txs independent; block body validation ensures no conflicts
                .enumerate()
                .skip(1) // Skip coinbase tx
                .filter_map(|(i, tx)| {
                    self.validate_transaction_in_utxo_context(
                        tx,
                        utxo_view,
                        pov_daa_score,
                        flags
                    ).ok().map(|vtx| (vtx, i as u32))
                })
                .collect()
        })
    }

    /// Attempts to populate the transaction with UTXO entries and performs all utxo-related tx validations
    fn validate_transaction_in_utxo_context<'a>(
        &self,
        transaction: &'a Transaction,
        utxo_view: &impl UtxoView,
        pov_daa_score: u64,
        flags: TxValidationFlags,
    ) -> TxResult<ValidatedTransaction<'a>> {
        let mut entries = Vec::with_capacity(transaction.inputs.len());
        let tx_id = transaction.id();
        
        cryptix_core::debug!("Validating TX {} in UTXO context, DAA score: {}", tx_id, pov_daa_score);
        
        // Check if this is a contract transaction by examining the payload
        let is_contract_tx = transaction.payload.len() >= 3 && &transaction.payload[0..3] == b"CX\x01";
        let mut contract_id = None;
        let mut action_id = None;
        
        if is_contract_tx {
            // Try to parse contract payload to extract contract_id and action_id
            if let Ok(payload) = cryptix_consensus_core::contract::ContractPayload::parse(&transaction.payload) {
                contract_id = Some(payload.c);
                action_id = Some(payload.a);
                
                // Log contract transaction details at INFO level for better visibility
                if payload.a == 0 {
                    // Deploy operation
                    info!("[CONTRACT_DEPLOY] Transaction {} deploying contract_id={}", tx_id, payload.c);
                } else {
                    // Execution operation
                    info!("[CONTRACT_EXEC] Transaction {} executing contract_id={}, action_id={}", 
                          tx_id, payload.c, payload.a);
                }
            }
        }
        
        for input in transaction.inputs.iter() {
            if let Some(entry) = utxo_view.get(&input.previous_outpoint) {
                // Check if this input is a contract state input
                if cryptix_txscript::is_contract_script(entry.script_public_key.script()) {
                    if let Some(cid) = cryptix_txscript::extract_contract_id(entry.script_public_key.script()) {
                        info!("[CONTRACT_STATE_INPUT] Transaction {} using contract state from {}:{} (contract_id={})", 
                              tx_id, input.previous_outpoint.transaction_id, input.previous_outpoint.index, cid);
                    }
                }
                entries.push(entry);
            } else {
                // Missing at least one input. For perf considerations, we report once a single miss is detected and avoid collecting all possible misses.
                cryptix_core::debug!("Missing UTXO for outpoint: {}", input.previous_outpoint);
                return Err(TxRuleError::MissingTxOutpoints);
            }
        }

        // NOTE: ContractAlreadyDeployed check has been removed.
        // Multiple users can deploy their own instances of the same contract type.
        // Each instance is uniquely identified by txid:output_index.
        // The UTXO mechanism already prevents duplicate transactions.

        let populated_tx = PopulatedTransaction::new(transaction, entries);
        
        // Enforce deploy/execution state rules in UTXO context (Phase 3c/3d)
        cryptix_core::debug!("Validating contract state rules for TX {}", tx_id);
        if let Err(e) = self.transaction_validator.validate_contract_state_rules(&populated_tx, pov_daa_score) {
            cryptix_core::debug!("Contract state rules validation failed for {}: {:?}", tx_id, e);
            return Err(e);
        }
        cryptix_core::debug!("Contract state rules validation passed for {}", tx_id);
        
        // Execute contract engine and verify state transition (Phase 4)
        cryptix_core::debug!("Applying contract engine for TX {}", tx_id);
        if let Err(e) = self.transaction_validator.apply_contract_engine_if_needed(&populated_tx, pov_daa_score) {
            cryptix_core::debug!("Contract engine application failed for {}: {:?}", tx_id, e);
            return Err(e);
        }
        cryptix_core::debug!("Contract engine application passed for {}", tx_id);
        
        let res = self.transaction_validator.validate_populated_transaction_and_get_fee(&populated_tx, pov_daa_score, flags, None);
        match res {
            Ok(calculated_fee) => {
                cryptix_core::debug!("Transaction {} validated successfully, fee: {}", tx_id, calculated_fee);
                
                // For contract transactions, log the state output information
                if is_contract_tx {
                    // Find contract state output
                    for (i, output) in transaction.outputs.iter().enumerate() {
                        if cryptix_txscript::is_contract_script(output.script_public_key.script()) {
                            if let Some(cid) = cryptix_txscript::extract_contract_id(output.script_public_key.script()) {
                                // This is a contract state output
                                if let Some(contract_id_from_payload) = contract_id {
                                    if cid == contract_id_from_payload {
                                        // Log the instance ID (txid:vout) for this contract state
                                        let instance_id = format!("{}:{}", tx_id, i);
                                        
                                        if action_id.unwrap_or(0) == 0 {
                                            // Deploy operation
                                            info!(" [CONTRACT_INSTANCE] Contract instance_id={} created for contract_id={}", 
                                                  instance_id, cid);
                                        } else {
                                            // Execution operation
                                            info!("[CONTRACT_INSTANCE] Contract instance_id={} updated for contract_id={}, action_id={}", 
                                                  instance_id, cid, action_id.unwrap_or(0));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                
                Ok(ValidatedTransaction::new(populated_tx, calculated_fee))
            },
            Err(tx_rule_error) => {
                info!("Rejecting transaction {} due to transaction rule error: {} (details: {:?})", 
                      tx_id, tx_rule_error, tx_rule_error);
                Err(tx_rule_error)
            }
        }
    }

    /// Populates the mempool transaction with maximally found UTXO entry data
    pub(crate) fn populate_mempool_transaction_in_utxo_context(
        &self,
        mutable_tx: &mut MutableTransaction,
        utxo_view: &impl UtxoView,
    ) -> TxResult<()> {
        let mut has_missing_outpoints = false;
        for i in 0..mutable_tx.tx.inputs.len() {
            if mutable_tx.entries[i].is_some() {
                // We prefer a previously populated entry if such exists
                continue;
            }
            if let Some(entry) = utxo_view.get(&mutable_tx.tx.inputs[i].previous_outpoint) {
                mutable_tx.entries[i] = Some(entry);
            } else {
                // We attempt to fill as much as possible UTXO entries, hence we do not break in this case but rather continue looping
                has_missing_outpoints = true;
            }
        }
        if has_missing_outpoints {
            return Err(TxRuleError::MissingTxOutpoints);
        }
        Ok(())
    }

    /// Populates the mempool transaction with maximally found UTXO entry data and proceeds to validation if all found
    pub(super) fn validate_mempool_transaction_in_utxo_context(
        &self,
        mutable_tx: &mut MutableTransaction,
        utxo_view: &impl UtxoView,
        pov_daa_score: u64,
        args: &TransactionValidationArgs,
    ) -> TxResult<()> {
        self.populate_mempool_transaction_in_utxo_context(mutable_tx, utxo_view)?;

        // For non-activated nets (mainnet, TN10) we can update mempool rules to KIP9 beta asap. For
        // TN11 we need to hard-fork consensus first (since the new beta rules are more permissive)
        let kip9_version = if self.storage_mass_activation_daa_score == u64::MAX { Kip9Version::Beta } else { Kip9Version::Alpha };

        // Calc the full contextual mass including storage mass
        let contextual_mass = self
            .transaction_validator
            .mass_calculator
            .calc_tx_overall_mass(&mutable_tx.as_verifiable(), mutable_tx.calculated_compute_mass, kip9_version)
            .ok_or(TxRuleError::MassIncomputable)?;

        // Set the inner mass field
        mutable_tx.tx.set_mass(contextual_mass);

        // At this point we know all UTXO entries are populated, so we can safely pass the tx as verifiable
        let mass_and_feerate_threshold = args.feerate_threshold.map(|threshold| (contextual_mass, threshold));
        let calculated_fee = self.transaction_validator.validate_populated_transaction_and_get_fee(
            &mutable_tx.as_verifiable(),
            pov_daa_score,
            TxValidationFlags::SkipMassCheck, // we can skip the mass check since we just set it
            mass_and_feerate_threshold,
        )?;
        mutable_tx.calculated_fee = Some(calculated_fee);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::ConfigBuilder,
        consensus::test_consensus::TestConsensus,
        params::MAINNET_PARAMS,
        processes::transaction_validator::transaction_validator_populated::TxValidationFlags,
    };
    use cryptix_consensus_core::{
        contract::ContractPayload,
        subnets::SUBNETWORK_ID_NATIVE,
        tx::{ScriptPublicKey, ScriptVec, Transaction, TransactionOutpoint, TransactionOutput, UtxoEntry},
    };
    use cryptix_core::assert_match;
    use cryptix_hashes::Hash;
    use cryptix_txscript::pay_to_contract_script;
    use crate::model::stores::utxo_set::UtxoSetStore;

     // Test: Multiple deployments of the same contract type are now allowed
     // Each instance is uniquely identified by txid:output_index
     #[tokio::test]
     async fn multiple_contract_deployments_are_allowed() {
        // Configure hardforks so contract payloads are parsed
        let config = ConfigBuilder::new(MAINNET_PARAMS)
            .skip_proof_of_work()
            .edit_consensus_params(|p| {
                p.non_coinbase_payload_activation_daa_score = 0;
                p.max_non_coinbase_payload_len = 40 * 1024;
                p.contracts_hardfork_daa_score = 100;
            })
            .build();
        let tc = TestConsensus::new(&config);
        let wait_handles = tc.init();

        // Pre-populate the virtual UTXO set with a state UTXO for contract_id = cid
        // This simulates that someone already deployed an instance of this contract
        let cid = 1u64; // Use Echo contract which is registered
        let state_script_bytes = pay_to_contract_script(cid);
        let state_spk = ScriptPublicKey::new(0, ScriptVec::from_slice(&state_script_bytes));
        let state_entry = UtxoEntry::new(0, state_spk, 0, false);
        let outpoint = TransactionOutpoint::new(Hash::from_slice(&[1u8; 32]), 0);
        let virtual_stores = tc.virtual_stores();
        {
            let mut vs = virtual_stores.write();
            UtxoSetStore::write_many(&mut vs.utxo_set, &[(outpoint, state_entry)]).unwrap();
        }

        // Build a deployment transaction for the same contract_id (a == 0)
        // This should now succeed since multiple instances are allowed
        let cp = ContractPayload { v: 1, c: cid, a: 0, d: vec![] };
        let encoded_payload = cp.encode().expect("encode contract payload");
        let deploy_script_bytes = pay_to_contract_script(cid);
        let deploy_spk = ScriptPublicKey::new(0, ScriptVec::from_slice(&deploy_script_bytes));
        let tx = Transaction::new(
            0,
            vec![], // no inputs required for deployment
            vec![TransactionOutput { value: 0, script_public_key: deploy_spk, payload: vec![] }],
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            encoded_payload,
        );

        // Call the contextual validator - should succeed now
        let vp = tc.virtual_processor();
        let virtual_stores = tc.virtual_stores();
        let virtual_read = virtual_stores.read();
        let utxo_view = &virtual_read.utxo_set;

        // This should succeed - multiple deployments are allowed
        let res = vp.validate_transaction_in_utxo_context(&tx, utxo_view, 100, TxValidationFlags::Full).map(|_| ());
        assert_match!(res, Ok(()));

        tc.shutdown(wait_handles);
     }

     // Phase 6: Execution after pruning-like conditions (state-only) is valid.
     // This simulates a node that, after pruning/restart, retains only the current UTXO state entry,
     // and executes a contract action based solely on the input UTXO payload without any global state.
     #[tokio::test]
     async fn execution_after_pruning_like_state_only_is_ok() {
         use cryptix_consensus_core::contract::ContractPayload;
         use cryptix_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
         use cryptix_consensus_core::tx::{ScriptPublicKey, ScriptVec, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry};
         use cryptix_txscript::pay_to_contract_script;
         use crate::model::stores::utxo_set::UtxoSetStore;

         // Configure hardforks so contract payloads are parsed and state rules are active
         let config = ConfigBuilder::new(MAINNET_PARAMS)
             .skip_proof_of_work()
             .edit_consensus_params(|p| {
                 p.non_coinbase_payload_activation_daa_score = 0;
                 p.max_non_coinbase_payload_len = 40 * 1024;
                 p.contracts_hardfork_daa_score = 100;
             })
             .build();
         let tc = TestConsensus::new(&config);
         let wait_handles = tc.init();

         // Choose a built-in contract (counter = 2). Counter increments u64-le state or empty (0) by 1.
         let cid = 2u64;

         // Simulate the "current state" UTXO present in the UTXO set after pruning/restart.
         // Old state is empty bytes => interpreted by the contract as 0.
         let state_script = ScriptPublicKey::new(0, ScriptVec::from_slice(&pay_to_contract_script(cid)));
         let state_entry = UtxoEntry::new(0, state_script, 0, false);
         let outpoint = TransactionOutpoint::new(Hash::from_slice(&[3u8; 32]), 0);

         // Write the current state entry into the virtual UTXO set
         {
             let binding = tc.virtual_stores();
             let mut vs = binding.write();
             UtxoSetStore::write_many(&mut vs.utxo_set, &[(outpoint, state_entry)]).unwrap();
         }

         // Build an execution transaction which spends the above state and creates the next state.
         // Expected new state for CounterContract: 1u64 in little-endian.
         let expected_state = 1u64.to_le_bytes().to_vec();

         let tx = Transaction::new(
             0,
             vec![TransactionInput {
                 previous_outpoint: outpoint,
                 signature_script: vec![], // Script checks are skipped for contract state inputs
                 sequence: 0,
                 sig_op_count: 0,
             }],
             vec![TransactionOutput {
                 value: 0,
                 script_public_key: ScriptPublicKey::new(0, ScriptVec::from_slice(&pay_to_contract_script(cid))),
                 payload: expected_state.clone(),
             }],
             0,
             SUBNETWORK_ID_NATIVE,
             0,
             // Execution payload (a > 0), no data required for counter
             ContractPayload { v: 1, c: cid, a: 1, d: vec![] }.encode().unwrap(),
         );

         // Validate in UTXO context: should succeed purely based on the UTXO-set state.
         let vp = tc.virtual_processor();
         let binding = tc.virtual_stores();
         let virtual_read = binding.read();
         let utxo_view = &virtual_read.utxo_set;

         let res = vp.validate_transaction_in_utxo_context(&tx, utxo_view, 100, TxValidationFlags::Full).map(|_| ());
         assert_match!(res, Ok(()));

         tc.shutdown(wait_handles);
     }

     // Phase 6: Deploy + exec + "prune-like" replay.
     // We simulate a full lifecycle:
     // 1) Validate a deploy TX (engine validates new state)
     // 2) Commit its state output into UTXO set (simulating block application)
     // 3) Validate an execution TX that spends that state and creates the next state
     // 4) Simulate pruning/restart by creating a fresh consensus and writing only the latest state UTXO
     // 5) Validate another execution solely based on that state (replay/IBD safety)
     #[tokio::test]
     async fn deploy_exec_then_pruning_like_replay_is_ok() {
         use cryptix_consensus_core::contract::ContractPayload;
         use cryptix_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
         use cryptix_consensus_core::tx::{
             ScriptPublicKey, ScriptVec, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
         };
         use cryptix_txscript::pay_to_contract_script;
         use crate::model::stores::utxo_set::UtxoSetStore;

         // Configure contracts
         let config = ConfigBuilder::new(MAINNET_PARAMS)
             .skip_proof_of_work()
             .edit_consensus_params(|p| {
                 p.non_coinbase_payload_activation_daa_score = 0;
                 p.max_non_coinbase_payload_len = 40 * 1024;
                 p.contracts_hardfork_daa_score = 100;
             })
             .build();

         // Use Echo contract (cid = 1) which returns data as new state
         let cid = 1u64;

         // 1) DEPLOY: engine should accept and match the state output payload
         let deploy_data = b"hello-state".to_vec(); // engine result for Echo
         let deploy_payload = ContractPayload { v: 1, c: cid, a: 0, d: deploy_data.clone() }.encode().unwrap();
         let deploy_tx = Transaction::new(
             0,
             vec![], // no inputs; value==0 state output so no fee needed
             vec![TransactionOutput {
                 value: 0,
                 script_public_key: ScriptPublicKey::new(0, ScriptVec::from_slice(&pay_to_contract_script(cid))),
                 payload: deploy_data.clone(),
             }],
             0,
             SUBNETWORK_ID_NATIVE,
             0,
             deploy_payload,
         );

         let tc = TestConsensus::new(&config);
         let wait_handles = tc.init();
         let vp = tc.virtual_processor();
         let vs_binding = tc.virtual_stores();
         let virtual_read = vs_binding.read();
         let utxo_view = &virtual_read.utxo_set;

         // Validate deploy in context
         let res = vp.validate_transaction_in_utxo_context(&deploy_tx, utxo_view, 100, TxValidationFlags::Full).map(|_| ());
         assert_match!(res, Ok(()));
         drop(virtual_read);

         // 2) Commit deploy: add the state output to UTXO set with a chosen outpoint
         let deploy_outpoint = TransactionOutpoint::new(Hash::from_slice(&[4u8; 32]), 0);
         let state_spk = ScriptPublicKey::new(0, ScriptVec::from_slice(&pay_to_contract_script(cid)));
         let deploy_state_entry = UtxoEntry::new_with_payload(0, state_spk, 0, false, deploy_data.clone());
         {
             let binding = tc.virtual_stores();
             let mut vs = binding.write();
             UtxoSetStore::write_many(&mut vs.utxo_set, &[(deploy_outpoint, deploy_state_entry)]).unwrap();
         }

         // 3) EXECUTION: spend deploy state and create next state
         let exec_data = b"next-state".to_vec(); // Echo returns this
         let exec_payload = ContractPayload { v: 1, c: cid, a: 1, d: exec_data.clone() }.encode().unwrap();
         let exec_tx = Transaction::new(
             0,
             vec![TransactionInput {
                 previous_outpoint: deploy_outpoint,
                 signature_script: vec![],
                 sequence: 0,
                 sig_op_count: 0,
             }],
             vec![TransactionOutput {
                 value: 0,
                 script_public_key: ScriptPublicKey::new(0, ScriptVec::from_slice(&pay_to_contract_script(cid))),
                 payload: exec_data.clone(),
             }],
             0,
             SUBNETWORK_ID_NATIVE,
             0,
             exec_payload,
         );

         let vs_binding2 = tc.virtual_stores();
         let virtual_read = vs_binding2.read();
         let utxo_view = &virtual_read.utxo_set;
         let res = vp.validate_transaction_in_utxo_context(&exec_tx, utxo_view, 100, TxValidationFlags::Full).map(|_| ());
         assert_match!(res, Ok(()));
         drop(virtual_read);

         // Apply "exec" by writing its state as the current UTXO (simulate block application)
         let exec_outpoint = TransactionOutpoint::new(Hash::from_slice(&[5u8; 32]), 0);
         let exec_state_entry = UtxoEntry::new_with_payload(
             0,
             ScriptPublicKey::new(0, ScriptVec::from_slice(&pay_to_contract_script(cid))),
             0,
             false,
             exec_data.clone(),
         );
         {
             let binding = tc.virtual_stores();
             let mut vs = binding.write();
             UtxoSetStore::write_many(&mut vs.utxo_set, &[(exec_outpoint, exec_state_entry)]).unwrap();
         }

         // Simulate pruning/restart: shutdown and new consensus with only the latest state
         tc.shutdown(wait_handles);

         let tc2 = TestConsensus::new(&config);
         let wait_handles2 = tc2.init();
         {
             let binding2 = tc2.virtual_stores();
             let mut vs2 = binding2.write();
             UtxoSetStore::write_many(
                 &mut vs2.utxo_set,
                 &[(
                     exec_outpoint,
                     UtxoEntry::new_with_payload(
                         0,
                         ScriptPublicKey::new(0, ScriptVec::from_slice(&pay_to_contract_script(cid))),
                         0,
                         false,
                         exec_data.clone(),
                     ),
                 )],
             )
             .unwrap();
         }

         // 5) Validate another execution relying solely on the current state entry
         let exec2_data = b"final-state".to_vec();
         let exec2_payload = ContractPayload { v: 1, c: cid, a: 1, d: exec2_data.clone() }.encode().unwrap();
         let exec2_tx = Transaction::new(
             0,
             vec![TransactionInput {
                 previous_outpoint: exec_outpoint,
                 signature_script: vec![],
                 sequence: 0,
                 sig_op_count: 0,
             }],
             vec![TransactionOutput {
                 value: 0,
                 script_public_key: ScriptPublicKey::new(0, ScriptVec::from_slice(&pay_to_contract_script(cid))),
                 payload: exec2_data.clone(),
             }],
             0,
             SUBNETWORK_ID_NATIVE,
             0,
             exec2_payload,
         );

         let vp2 = tc2.virtual_processor();
         let binding2 = tc2.virtual_stores();
         let virtual_read2 = binding2.read();
         let utxo_view2 = &virtual_read2.utxo_set;
         let res2 = vp2.validate_transaction_in_utxo_context(&exec2_tx, utxo_view2, 100, TxValidationFlags::Full).map(|_| ());
         assert_match!(res2, Ok(()));

         tc2.shutdown(wait_handles2);
     }

     // Phase 6: Pruned-context engine mismatch should be rejected.
     // Echo contract (cid=1) returns exactly the data 'd'. We set a different state output payload to trigger InvalidContractState.
     #[tokio::test]
     async fn execution_after_pruning_like_engine_mismatch_is_rejected() {
         use cryptix_consensus_core::contract::ContractPayload;
         use cryptix_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
         use cryptix_consensus_core::tx::{ScriptPublicKey, ScriptVec, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry};
         use cryptix_txscript::pay_to_contract_script;
         use crate::model::stores::utxo_set::UtxoSetStore;

         // Configure contracts
         let config = ConfigBuilder::new(MAINNET_PARAMS)
             .skip_proof_of_work()
             .edit_consensus_params(|p| {
                 p.non_coinbase_payload_activation_daa_score = 0;
                 p.max_non_coinbase_payload_len = 40 * 1024;
                 p.contracts_hardfork_daa_score = 100;
             })
             .build();

         let tc = TestConsensus::new(&config);
         let wait_handles = tc.init();

         // Echo contract id
         let cid = 1u64;

         // Seed UTXO state for the contract (empty state is fine for echo)
         let state_spk = ScriptPublicKey::new(0, ScriptVec::from_slice(&pay_to_contract_script(cid)));
         let state_entry = UtxoEntry::new(0, state_spk, 0, false);
         let outpoint = TransactionOutpoint::new(Hash::from_slice(&[7u8; 32]), 0);
         {
             let vs_binding = tc.virtual_stores();
             let mut vs = vs_binding.write();
             UtxoSetStore::write_many(&mut vs.utxo_set, &[(outpoint, state_entry)]).unwrap();
         }

         // Build execution with mismatching engine output vs tx payload
         let correct_engine_data = b"right".to_vec();
         let wrong_state_payload = b"wrong".to_vec();

         let tx = Transaction::new(
             0,
             vec![TransactionInput {
                 previous_outpoint: outpoint,
                 signature_script: vec![],
                 sequence: 0,
                 sig_op_count: 0,
             }],
             vec![TransactionOutput {
                 value: 0,
                 script_public_key: ScriptPublicKey::new(0, ScriptVec::from_slice(&pay_to_contract_script(cid))),
                 payload: wrong_state_payload,
             }],
             0,
             SUBNETWORK_ID_NATIVE,
             0,
             ContractPayload { v: 1, c: cid, a: 1, d: correct_engine_data }.encode().unwrap(),
         );

         let vp = tc.virtual_processor();
         let vs_binding = tc.virtual_stores();
         let virtual_read = vs_binding.read();
         let utxo_view = &virtual_read.utxo_set;

         let res = vp.validate_transaction_in_utxo_context(&tx, utxo_view, 100, TxValidationFlags::Full).map(|_| ());
         assert_match!(res, Err(TxRuleError::InvalidContractState(id)) if id == cid);

         tc.shutdown(wait_handles);
     }

     // Phase 6: Pruned-context state too large should be rejected.
     // Using Echo contract (cid=1), we craft an oversized state payload and expect StateTooLarge.
     #[tokio::test]
     async fn execution_after_pruning_like_state_too_large_is_rejected() {
         use cryptix_consensus_core::contract::{ContractPayload, MAX_CONTRACT_STATE_SIZE};
         use cryptix_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
         use cryptix_consensus_core::tx::{ScriptPublicKey, ScriptVec, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry};
         use cryptix_txscript::pay_to_contract_script;
         use crate::model::stores::utxo_set::UtxoSetStore;

         // Configure contracts
         let config = ConfigBuilder::new(MAINNET_PARAMS)
             .skip_proof_of_work()
             .edit_consensus_params(|p| {
                 p.non_coinbase_payload_activation_daa_score = 0;
                 p.max_non_coinbase_payload_len = 40 * 1024;
                 p.contracts_hardfork_daa_score = 100;
             })
             .build();

         let tc = TestConsensus::new(&config);
         let wait_handles = tc.init();

         // Echo contract id
         let cid = 1u64;

         // Seed UTXO state for the contract
         let state_spk = ScriptPublicKey::new(0, ScriptVec::from_slice(&pay_to_contract_script(cid)));
         let state_entry = UtxoEntry::new(0, state_spk, 0, false);
         let outpoint = TransactionOutpoint::new(Hash::from_slice(&[8u8; 32]), 0);
         {
             let vs_binding = tc.virtual_stores();
             let mut vs = vs_binding.write();
             UtxoSetStore::write_many(&mut vs.utxo_set, &[(outpoint, state_entry)]).unwrap();
         }

         // Oversized state
         let oversized = vec![0u8; MAX_CONTRACT_STATE_SIZE + 1];

         let tx = Transaction::new(
             0,
             vec![TransactionInput {
                 previous_outpoint: outpoint,
                 signature_script: vec![],
                 sequence: 0,
                 sig_op_count: 0,
             }],
             vec![TransactionOutput {
                 value: 0,
                 script_public_key: ScriptPublicKey::new(0, ScriptVec::from_slice(&pay_to_contract_script(cid))),
                 payload: oversized.clone(),
             }],
             0,
             SUBNETWORK_ID_NATIVE,
             0,
             // Echo returns d verbatim, so this will also be oversized
             ContractPayload { v: 1, c: cid, a: 1, d: oversized }.encode().unwrap(),
         );

         let vp = tc.virtual_processor();
         let vs_binding = tc.virtual_stores();
         let virtual_read = vs_binding.read();
         let utxo_view = &virtual_read.utxo_set;

         let res = vp.validate_transaction_in_utxo_context(&tx, utxo_view, 100, TxValidationFlags::Full).map(|_| ());
         assert_match!(res, Err(TxRuleError::StateTooLarge(_, _)));

         tc.shutdown(wait_handles);
     }
}
