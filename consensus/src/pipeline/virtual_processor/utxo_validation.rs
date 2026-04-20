use super::VirtualStateProcessor;
use crate::{
    errors::{
        BlockProcessResult,
        RuleError::{BadAcceptedIDMerkleRoot, BadCoinbaseTransaction, BadUTXOCommitment, InvalidTransactionsInUtxoContext},
    },
    model::stores::{
        atomic_state::{AtomicAssetState, AtomicBalanceKey, AtomicConsensusState, AtomicSupplyMode},
        block_transactions::BlockTransactionsStoreReader,
        daa::DaaStoreReader,
        ghostdag::GhostdagData,
    },
    processes::transaction_validator::{
        errors::{TxResult, TxRuleError},
        transaction_validator_populated::{
            atomic_owner_id_from_script, parse_atomic_payload, AtomicPayloadOp, AtomicPayloadSupplyMode, TxValidationFlags,
        },
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
use std::{
    collections::{HashMap, HashSet},
    iter::once,
    ops::Deref,
};

/// A context for processing the UTXO state of a block with respect to its selected parent.
/// Note this can also be the virtual block.
pub(super) struct UtxoProcessingContext<'a> {
    pub ghostdag_data: Refs<'a, GhostdagData>,
    pub multiset_hash: MuHash,
    pub mergeset_diff: UtxoDiff,
    pub accepted_tx_ids: Vec<TransactionId>,
    pub mergeset_acceptance_data: Vec<MergesetBlockAcceptanceData>,
    pub mergeset_rewards: BlockHashMap<BlockRewardData>,
    pub atomic_state: AtomicConsensusState,
}

impl<'a> UtxoProcessingContext<'a> {
    pub fn new(
        ghostdag_data: Refs<'a, GhostdagData>,
        selected_parent_multiset_hash: MuHash,
        selected_parent_atomic_state: AtomicConsensusState,
    ) -> Self {
        let mergeset_size = ghostdag_data.mergeset_size();
        Self {
            ghostdag_data,
            multiset_hash: selected_parent_multiset_hash,
            mergeset_diff: UtxoDiff::default(),
            accepted_tx_ids: Vec::with_capacity(1), // We expect at least the selected parent coinbase tx
            mergeset_rewards: BlockHashMap::with_capacity(mergeset_size),
            mergeset_acceptance_data: Vec::with_capacity(mergeset_size),
            atomic_state: selected_parent_atomic_state,
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
            let mut validated_transactions =
                self.validate_transactions_in_parallel(&txs, &composed_view, pov_daa_score, validation_flags);
            validated_transactions =
                self.filter_validated_transactions_by_atomic_state(validated_transactions, pov_daa_score, &mut ctx.atomic_state);

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
        let mut validated_transactions =
            self.validate_transactions_in_parallel(&txs, &current_utxo_view, header.daa_score, TxValidationFlags::Full);
        let mut atomic_state = ctx.atomic_state.clone();
        validated_transactions =
            self.filter_validated_transactions_by_atomic_state(validated_transactions, header.daa_score, &mut atomic_state);
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
                .par_iter() // We can do this in parallel without complications since block body validation already ensured
                            // that all txs within each block are independent
                .enumerate()
                .skip(1) // Skip the coinbase tx.
                .filter_map(|(i, tx)| self.validate_transaction_in_utxo_context(tx, &utxo_view, pov_daa_score, flags).ok().map(|vtx| (vtx, i as u32)))
                .collect()
        })
    }

    fn filter_validated_transactions_by_atomic_state<'a>(
        &self,
        mut validated_transactions: Vec<(ValidatedTransaction<'a>, u32)>,
        pov_daa_score: u64,
        atomic_state: &mut AtomicConsensusState,
    ) -> Vec<(ValidatedTransaction<'a>, u32)> {
        validated_transactions.sort_by_key(|(_, tx_index)| *tx_index);

        let mut filtered = Vec::with_capacity(validated_transactions.len());
        for (validated_tx, tx_index) in validated_transactions.into_iter() {
            let tx_id = validated_tx.id();
            match self.validate_and_apply_atomic_state_transition(&validated_tx, pov_daa_score, atomic_state) {
                Ok(()) => filtered.push((validated_tx, tx_index)),
                Err(err) => {
                    info!("Rejecting transaction {} due to transaction rule error at block tx index {}: {}", tx_id, tx_index, err);
                }
            }
        }

        filtered
    }

    pub(crate) fn validate_and_apply_atomic_state_transition(
        &self,
        tx: &impl VerifiableTransaction,
        pov_daa_score: u64,
        atomic_state: &mut AtomicConsensusState,
    ) -> TxResult<()> {
        let payload_hf_active = self.transaction_validator.is_payload_hf_active(pov_daa_score);

        let tx_ref = tx.tx();
        if !payload_hf_active || !tx_ref.subnetwork_id.is_payload() || tx_ref.payload.is_empty() {
            self.apply_anchor_deltas_to_atomic_state(tx, atomic_state);
            return Ok(());
        }

        let Some(parsed_payload) = parse_atomic_payload(tx_ref.payload.as_slice()).map_err(TxRuleError::InvalidAtomicPayload)? else {
            self.apply_anchor_deltas_to_atomic_state(tx, atomic_state);
            return Ok(());
        };
        let owner_id = self.resolve_atomic_owner_from_populated_tx(tx, parsed_payload.auth_input_index)?;

        let expected_nonce = atomic_state.next_nonces.get(&owner_id).copied().unwrap_or(1);
        if parsed_payload.nonce != expected_nonce {
            return Err(TxRuleError::InvalidAtomicPayload(format!(
                "nonce baseline violation for owner `{}`: expected `{}`, got `{}`",
                faster_hex::hex_string(&owner_id),
                expected_nonce,
                parsed_payload.nonce
            )));
        }

        self.validate_replacement_anchor(tx, owner_id, atomic_state)?;
        self.apply_atomic_op_to_state(tx.tx().id().as_bytes(), owner_id, parsed_payload.op, atomic_state)?;

        let Some(next_nonce) = expected_nonce.checked_add(1) else {
            return Err(TxRuleError::InvalidAtomicPayload(format!(
                "nonce progression overflow for owner `{}`",
                faster_hex::hex_string(&owner_id)
            )));
        };
        atomic_state.next_nonces.insert(owner_id, next_nonce);
        self.apply_anchor_deltas_to_atomic_state(tx, atomic_state);
        Ok(())
    }

    fn resolve_atomic_owner_from_populated_tx(&self, tx: &impl VerifiableTransaction, auth_input_index: u16) -> TxResult<[u8; 32]> {
        let auth_input_index = auth_input_index as usize;
        let (_, auth_entry) = tx.populated_inputs().nth(auth_input_index).ok_or_else(|| {
            TxRuleError::InvalidAtomicPayload(format!(
                "auth_input_index `{auth_input_index}` has no populated UTXO entry in contextual validation"
            ))
        })?;
        atomic_owner_id_from_script(&auth_entry.script_public_key).ok_or_else(|| {
            TxRuleError::InvalidAtomicPayload(
                "auth input script public key is not a supported CAT owner authorization scheme (expected PubKey, PubKeyECDSA, or ScriptHash)"
                    .to_string(),
            )
        })
    }

    fn validate_replacement_anchor(
        &self,
        tx: &impl VerifiableTransaction,
        owner_id: [u8; 32],
        atomic_state: &AtomicConsensusState,
    ) -> TxResult<()> {
        let before_count = atomic_state.anchor_counts.get(&owner_id).copied().unwrap_or(0);
        let mut spent_for_owner = 0u64;
        for (_, entry) in tx.populated_inputs() {
            if atomic_owner_id_from_script(&entry.script_public_key) == Some(owner_id) {
                spent_for_owner = spent_for_owner.saturating_add(1);
            }
        }

        if before_count.saturating_sub(spent_for_owner) > 0 {
            return Ok(());
        }

        let has_replacement_anchor =
            tx.tx().outputs.iter().any(|output| atomic_owner_id_from_script(&output.script_public_key) == Some(owner_id));
        if has_replacement_anchor {
            Ok(())
        } else {
            Err(TxRuleError::InvalidAtomicPayload(
                "auth owner would lose the final anchor UTXO without a replacement owner output".to_string(),
            ))
        }
    }

    fn apply_anchor_deltas_to_atomic_state(&self, tx: &impl VerifiableTransaction, atomic_state: &mut AtomicConsensusState) {
        let mut spent_counts: HashMap<[u8; 32], u64> = HashMap::new();
        for (_, entry) in tx.populated_inputs() {
            let Some(owner_id) = atomic_owner_id_from_script(&entry.script_public_key) else {
                continue;
            };
            *spent_counts.entry(owner_id).or_insert(0) += 1;
        }

        let mut created_counts: HashMap<[u8; 32], u64> = HashMap::new();
        for output in tx.tx().outputs.iter() {
            let Some(owner_id) = atomic_owner_id_from_script(&output.script_public_key) else {
                continue;
            };
            *created_counts.entry(owner_id).or_insert(0) += 1;
        }

        let owners: HashSet<[u8; 32]> = spent_counts.keys().copied().chain(created_counts.keys().copied()).collect();
        for owner_id in owners {
            let old_count = atomic_state.anchor_counts.get(&owner_id).copied().unwrap_or(0);
            let spent = spent_counts.get(&owner_id).copied().unwrap_or(0);
            let created = created_counts.get(&owner_id).copied().unwrap_or(0);
            let new_count = old_count.saturating_sub(spent).saturating_add(created);
            if new_count == 0 {
                atomic_state.anchor_counts.remove(&owner_id);
            } else {
                atomic_state.anchor_counts.insert(owner_id, new_count);
            }
        }
    }

    fn apply_atomic_op_to_state(
        &self,
        tx_id_bytes: [u8; 32],
        owner_id: [u8; 32],
        op: AtomicPayloadOp,
        atomic_state: &mut AtomicConsensusState,
    ) -> TxResult<()> {
        match op {
            AtomicPayloadOp::CreateAsset {
                decimals: _,
                supply_mode,
                max_supply,
                mint_authority_owner_id,
                name: _,
                symbol: _,
                metadata: _,
            } => {
                let asset_id = tx_id_bytes;
                if atomic_state.assets.contains_key(&asset_id) {
                    return Err(TxRuleError::InvalidAtomicPayload(format!(
                        "asset `{}` already exists",
                        faster_hex::hex_string(&asset_id)
                    )));
                }
                let supply_mode = match supply_mode {
                    AtomicPayloadSupplyMode::Uncapped => AtomicSupplyMode::Uncapped,
                    AtomicPayloadSupplyMode::Capped => AtomicSupplyMode::Capped,
                };
                atomic_state
                    .assets
                    .insert(asset_id, AtomicAssetState { mint_authority_owner_id, supply_mode, max_supply, total_supply: 0 });
            }
            AtomicPayloadOp::Transfer { asset_id, to_owner_id, amount } => {
                if !atomic_state.assets.contains_key(&asset_id) {
                    return Err(TxRuleError::InvalidAtomicPayload(format!(
                        "transfer references unknown asset `{}`",
                        faster_hex::hex_string(&asset_id)
                    )));
                }

                let from_key = AtomicBalanceKey { asset_id, owner_id };
                let to_key = AtomicBalanceKey { asset_id, owner_id: to_owner_id };

                let sender_balance = atomic_state.balances.get(&from_key).copied().unwrap_or(0);
                if from_key == to_key {
                    sender_balance.checked_sub(amount).ok_or_else(|| {
                        TxRuleError::InvalidAtomicPayload(format!(
                            "insufficient balance for self-transfer of asset `{}`",
                            faster_hex::hex_string(&asset_id)
                        ))
                    })?;
                } else {
                    let receiver_balance = atomic_state.balances.get(&to_key).copied().unwrap_or(0);
                    let sender_after = sender_balance.checked_sub(amount).ok_or_else(|| {
                        TxRuleError::InvalidAtomicPayload(format!(
                            "insufficient balance for transfer of asset `{}`",
                            faster_hex::hex_string(&asset_id)
                        ))
                    })?;
                    let receiver_after = receiver_balance.checked_add(amount).ok_or_else(|| {
                        TxRuleError::InvalidAtomicPayload(format!(
                            "balance overflow for transfer receiver in asset `{}`",
                            faster_hex::hex_string(&asset_id)
                        ))
                    })?;

                    if sender_after == 0 {
                        atomic_state.balances.remove(&from_key);
                    } else {
                        atomic_state.balances.insert(from_key, sender_after);
                    }
                    atomic_state.balances.insert(to_key, receiver_after);
                }
            }
            AtomicPayloadOp::Mint { asset_id, to_owner_id, amount } => {
                let mut asset = atomic_state.assets.get(&asset_id).cloned().ok_or_else(|| {
                    TxRuleError::InvalidAtomicPayload(format!("mint references unknown asset `{}`", faster_hex::hex_string(&asset_id)))
                })?;
                if asset.mint_authority_owner_id != owner_id {
                    return Err(TxRuleError::InvalidAtomicPayload(format!(
                        "owner `{}` is not mint authority for asset `{}`",
                        faster_hex::hex_string(&owner_id),
                        faster_hex::hex_string(&asset_id)
                    )));
                }

                let new_total_supply = asset.total_supply.checked_add(amount).ok_or_else(|| {
                    TxRuleError::InvalidAtomicPayload(format!(
                        "supply overflow while minting asset `{}`",
                        faster_hex::hex_string(&asset_id)
                    ))
                })?;
                if matches!(asset.supply_mode, AtomicSupplyMode::Capped) && new_total_supply > asset.max_supply {
                    return Err(TxRuleError::InvalidAtomicPayload(format!(
                        "mint would exceed cap for asset `{}`: cap `{}`, attempted total `{}`",
                        faster_hex::hex_string(&asset_id),
                        asset.max_supply,
                        new_total_supply
                    )));
                }

                let receiver_key = AtomicBalanceKey { asset_id, owner_id: to_owner_id };
                let receiver_balance = atomic_state.balances.get(&receiver_key).copied().unwrap_or(0);
                let receiver_after = receiver_balance.checked_add(amount).ok_or_else(|| {
                    TxRuleError::InvalidAtomicPayload(format!(
                        "balance overflow while minting asset `{}`",
                        faster_hex::hex_string(&asset_id)
                    ))
                })?;

                asset.total_supply = new_total_supply;
                atomic_state.assets.insert(asset_id, asset);
                atomic_state.balances.insert(receiver_key, receiver_after);
            }
            AtomicPayloadOp::Burn { asset_id, amount } => {
                let mut asset = atomic_state.assets.get(&asset_id).cloned().ok_or_else(|| {
                    TxRuleError::InvalidAtomicPayload(format!("burn references unknown asset `{}`", faster_hex::hex_string(&asset_id)))
                })?;
                let sender_key = AtomicBalanceKey { asset_id, owner_id };
                let sender_balance = atomic_state.balances.get(&sender_key).copied().unwrap_or(0);

                let sender_after = sender_balance.checked_sub(amount).ok_or_else(|| {
                    TxRuleError::InvalidAtomicPayload(format!(
                        "insufficient balance for burn in asset `{}`",
                        faster_hex::hex_string(&asset_id)
                    ))
                })?;
                let supply_after = asset.total_supply.checked_sub(amount).ok_or_else(|| {
                    TxRuleError::InvalidAtomicPayload(format!(
                        "supply underflow while burning asset `{}`",
                        faster_hex::hex_string(&asset_id)
                    ))
                })?;

                asset.total_supply = supply_after;
                atomic_state.assets.insert(asset_id, asset);
                if sender_after == 0 {
                    atomic_state.balances.remove(&sender_key);
                } else {
                    atomic_state.balances.insert(sender_key, sender_after);
                }
            }
        }
        Ok(())
    }

    /// Attempts to populate the transaction with UTXO entries and performs all utxo-related tx validations
    pub(super) fn validate_transaction_in_utxo_context<'a>(
        &self,
        transaction: &'a Transaction,
        utxo_view: &impl UtxoView,
        pov_daa_score: u64,
        flags: TxValidationFlags,
    ) -> TxResult<ValidatedTransaction<'a>> {
        let mut entries = Vec::with_capacity(transaction.inputs.len());
        for input in transaction.inputs.iter() {
            if let Some(entry) = utxo_view.get(&input.previous_outpoint) {
                entries.push(entry);
            } else {
                // Missing at least one input. For perf considerations, we report once a single miss is detected and avoid collecting all possible misses.
                return Err(TxRuleError::MissingTxOutpoints);
            }
        }
        let populated_tx = PopulatedTransaction::new(transaction, entries);
        let res = self.transaction_validator.validate_populated_transaction_and_get_fee(&populated_tx, pov_daa_score, flags, None);
        match res {
            Ok(calculated_fee) => Ok(ValidatedTransaction::new(populated_tx, calculated_fee)),
            Err(tx_rule_error) => {
                info!("Rejecting transaction {} due to transaction rule error: {}", transaction.id(), tx_rule_error);
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

        // For networks without storage-mass activation we can keep KIP9 beta mempool rules.
        // For activated networks we keep alpha until consensus activation catches up.
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
