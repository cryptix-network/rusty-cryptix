use super::VirtualStateProcessor;
use crate::{
    constants::{MAX_SOMPI, SOMPI_PER_CRYPTIX},
    errors::{
        BlockProcessResult,
        RuleError::{BadAcceptedIDMerkleRoot, BadCoinbaseTransaction, BadUTXOCommitment, InvalidTransactionsInUtxoContext},
    },
    model::stores::{
        atomic_state::{
            AtomicAssetClass, AtomicAssetState, AtomicBalanceKey, AtomicConsensusState, AtomicLiquidityFeeRecipientState,
            AtomicLiquidityPoolState, AtomicSupplyMode,
        },
        block_transactions::BlockTransactionsStoreReader,
        daa::DaaStoreReader,
        ghostdag::GhostdagData,
    },
    processes::transaction_validator::{
        errors::{TxResult, TxRuleError},
        transaction_validator_populated::{
            atomic_owner_id_from_address_components, atomic_owner_id_from_script, parse_atomic_payload, AtomicPayloadOp,
            AtomicPayloadRecipientAddress, AtomicPayloadSupplyMode, TxValidationFlags,
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
    tx::{
        MutableTransaction, PopulatedTransaction, Transaction, TransactionId, TransactionOutpoint, ValidatedTransaction,
        VerifiableTransaction,
    },
    utxo::{
        utxo_diff::UtxoDiff,
        utxo_view::{UtxoView, UtxoViewComposition},
    },
    BlockHashMap, BlockHashSet, HashMapCustomHasher,
};
use cryptix_core::{info, trace};
use cryptix_hashes::Hash;
use cryptix_math::Uint256;
use cryptix_muhash::MuHash;
use cryptix_txscript::script_class::ScriptClass;
use cryptix_utils::refs::Refs;

use rayon::prelude::*;
use std::{
    collections::{HashMap, HashSet},
    iter::once,
    ops::Deref,
};

// Allow dust-sized redemptions so the final outstanding liquidity tokens can always exit.
const LIQUIDITY_MIN_PAYOUT_SOMPI: u64 = 1;
const LIQUIDITY_TOKEN_DECIMALS: u8 = 0;
const MIN_LIQUIDITY_SUPPLY_RAW: u128 = 100_000;
const LIQUIDITY_TOKEN_SUPPLY_RAW: u128 = 1_000_000;
const MAX_LIQUIDITY_SUPPLY_RAW: u128 = 10_000_000;
const INITIAL_REAL_CPAY_RESERVES_SOMPI: u64 = SOMPI_PER_CRYPTIX;
const MIN_CPAY_RESERVE_SOMPI: u64 = 1;
const MIN_REAL_TOKEN_RESERVE: u128 = 1;
const INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI: u64 = 250_000_000_000_000;
const INITIAL_VIRTUAL_TOKEN_RESERVES: u128 = LIQUIDITY_TOKEN_SUPPLY_RAW * 6 / 5;

#[derive(Clone, Copy, Debug)]
struct VaultTransition {
    input_value: u64,
    output_index: u32,
    output_value: u64,
}

#[cfg(test)]
mod tests {
    use super::{
        atomic_op_allows_liquidity_vault_output, validate_liquidity_claim_authorization, validate_liquidity_creation_parameters,
        AtomicPayloadOp, INITIAL_REAL_CPAY_RESERVES_SOMPI, LIQUIDITY_TOKEN_SUPPLY_RAW, MAX_LIQUIDITY_SUPPLY_RAW,
        MIN_LIQUIDITY_SUPPLY_RAW,
    };

    #[test]
    fn liquidity_claims_require_matching_recipient_owner() {
        assert!(validate_liquidity_claim_authorization([0x22; 32], [0x22; 32]).is_ok());
        assert!(validate_liquidity_claim_authorization([0x22; 32], [0x33; 32]).is_err());
    }

    #[test]
    fn liquidity_creation_parameters_enforce_mainnet_limits() {
        assert!(validate_liquidity_creation_parameters(0, LIQUIDITY_TOKEN_SUPPLY_RAW, INITIAL_REAL_CPAY_RESERVES_SOMPI).is_ok());
        assert!(validate_liquidity_creation_parameters(0, MIN_LIQUIDITY_SUPPLY_RAW, INITIAL_REAL_CPAY_RESERVES_SOMPI).is_ok());
        assert!(validate_liquidity_creation_parameters(0, MAX_LIQUIDITY_SUPPLY_RAW, INITIAL_REAL_CPAY_RESERVES_SOMPI).is_ok());
        assert!(validate_liquidity_creation_parameters(1, LIQUIDITY_TOKEN_SUPPLY_RAW, INITIAL_REAL_CPAY_RESERVES_SOMPI).is_err());
        assert!(validate_liquidity_creation_parameters(0, MIN_LIQUIDITY_SUPPLY_RAW - 1, INITIAL_REAL_CPAY_RESERVES_SOMPI).is_err());
        assert!(validate_liquidity_creation_parameters(0, MAX_LIQUIDITY_SUPPLY_RAW + 1, INITIAL_REAL_CPAY_RESERVES_SOMPI).is_err());
        assert!(validate_liquidity_creation_parameters(0, LIQUIDITY_TOKEN_SUPPLY_RAW, INITIAL_REAL_CPAY_RESERVES_SOMPI - 1).is_err());
    }

    #[test]
    fn only_liquidity_ops_may_create_vault_outputs() {
        assert!(!atomic_op_allows_liquidity_vault_output(&AtomicPayloadOp::Transfer {
            asset_id: [0x44; 32],
            to_owner_id: [0x55; 32],
            amount: 1,
        }));
        assert!(atomic_op_allows_liquidity_vault_output(&AtomicPayloadOp::BuyLiquidityExactIn {
            asset_id: [0x44; 32],
            expected_pool_nonce: 1,
            cpay_in_sompi: 1,
            min_token_out: 1,
        }));
    }
}

fn calculate_trade_fee(amount: u64, fee_bps: u16) -> TxResult<u64> {
    let fee = (u128::from(amount))
        .checked_mul(u128::from(fee_bps))
        .ok_or_else(|| TxRuleError::InvalidAtomicPayload("fee multiplication overflow".to_string()))?
        / 10_000u128;
    u64::try_from(fee).map_err(|_| TxRuleError::InvalidAtomicPayload("fee does not fit into u64".to_string()))
}

fn cpmm_buy(
    real_token_reserves: u128,
    virtual_cpay_reserves_sompi: u64,
    virtual_token_reserves: u128,
    cpay_net_in: u64,
) -> TxResult<(u128, u128, u64, u128)> {
    if real_token_reserves <= MIN_REAL_TOKEN_RESERVE {
        return Err(TxRuleError::InvalidAtomicPayload("CPMM buy real token reserve floor reached".to_string()));
    }
    let x_after = virtual_cpay_reserves_sompi
        .checked_add(cpay_net_in)
        .ok_or_else(|| TxRuleError::InvalidAtomicPayload("CPMM x_after overflow".to_string()))?;
    if x_after == 0 || virtual_token_reserves == 0 {
        return Err(TxRuleError::InvalidAtomicPayload("CPMM buy x_after cannot be zero".to_string()));
    }

    let k = Uint256::from_u64(virtual_cpay_reserves_sompi) * Uint256::from_u128(virtual_token_reserves);
    let y_after_u256 = ceil_div_u256(k, Uint256::from_u64(x_after));
    let y_after = u128::try_from(y_after_u256)
        .map_err(|_| TxRuleError::InvalidAtomicPayload("CPMM buy y_after conversion overflow".to_string()))?;
    if y_after == 0 {
        return Err(TxRuleError::InvalidAtomicPayload("CPMM buy y_after cannot be zero".to_string()));
    }
    if y_after > virtual_token_reserves {
        return Err(TxRuleError::InvalidAtomicPayload("CPMM buy would increase y_after".to_string()));
    }

    let token_out = virtual_token_reserves
        .checked_sub(y_after)
        .ok_or_else(|| TxRuleError::InvalidAtomicPayload("CPMM buy token_out underflow".to_string()))?;
    if token_out == 0 {
        return Err(TxRuleError::InvalidAtomicPayload("CPMM buy produced zero token_out".to_string()));
    }
    let new_real_token_reserves = real_token_reserves
        .checked_sub(token_out)
        .ok_or_else(|| TxRuleError::InvalidAtomicPayload("CPMM buy real token reserve underflow".to_string()))?;
    if new_real_token_reserves < MIN_REAL_TOKEN_RESERVE {
        return Err(TxRuleError::InvalidAtomicPayload("CPMM buy would drain final real token".to_string()));
    }

    Ok((token_out, new_real_token_reserves, x_after, y_after))
}

fn cpmm_sell(
    real_cpay_reserves_sompi: u64,
    virtual_cpay_reserves_sompi: u64,
    virtual_token_reserves: u128,
    token_in: u128,
) -> TxResult<(u64, u64, u64, u128)> {
    let y_after = virtual_token_reserves
        .checked_add(token_in)
        .ok_or_else(|| TxRuleError::InvalidAtomicPayload("CPMM y_after overflow".to_string()))?;
    if y_after == 0 {
        return Err(TxRuleError::InvalidAtomicPayload("CPMM sell y_after cannot be zero".to_string()));
    }

    let x_before = virtual_cpay_reserves_sompi;
    let k = Uint256::from_u64(x_before) * Uint256::from_u128(virtual_token_reserves);
    let x_after_u256 = k / Uint256::from_u128(y_after);
    let x_after_u128 = u128::try_from(x_after_u256)
        .map_err(|_| TxRuleError::InvalidAtomicPayload("CPMM sell x_after conversion overflow".to_string()))?;
    let x_after = u64::try_from(x_after_u128)
        .map_err(|_| TxRuleError::InvalidAtomicPayload("CPMM sell x_after does not fit u64".to_string()))?;
    if x_after > x_before {
        return Err(TxRuleError::InvalidAtomicPayload("CPMM sell x_after exceeds x_before".to_string()));
    }

    let gross_out =
        x_before.checked_sub(x_after).ok_or_else(|| TxRuleError::InvalidAtomicPayload("CPMM sell gross_out underflow".to_string()))?;
    if gross_out == 0 {
        return Err(TxRuleError::InvalidAtomicPayload("CPMM sell produced zero gross_out".to_string()));
    }
    let new_real_cpay_reserves_sompi = real_cpay_reserves_sompi
        .checked_sub(gross_out)
        .ok_or_else(|| TxRuleError::InvalidAtomicPayload("CPMM sell real CPAY reserve underflow".to_string()))?;
    if new_real_cpay_reserves_sompi < MIN_CPAY_RESERVE_SOMPI {
        return Err(TxRuleError::InvalidAtomicPayload("CPMM sell would drain final real sompi".to_string()));
    }
    Ok((gross_out, new_real_cpay_reserves_sompi, x_after, y_after))
}

fn ceil_div_u256(numerator: Uint256, denominator: Uint256) -> Uint256 {
    let quotient = numerator / denominator;
    let remainder = numerator % denominator;
    if remainder.is_zero() {
        quotient
    } else {
        quotient + Uint256::from_u64(1)
    }
}

fn initial_virtual_token_reserves(max_supply: u128) -> TxResult<u128> {
    if !(MIN_LIQUIDITY_SUPPLY_RAW..=MAX_LIQUIDITY_SUPPLY_RAW).contains(&max_supply) {
        return Err(TxRuleError::InvalidAtomicPayload(format!(
            "liquidity asset max_supply must be in `{MIN_LIQUIDITY_SUPPLY_RAW}..={MAX_LIQUIDITY_SUPPLY_RAW}`"
        )));
    }
    max_supply
        .checked_mul(6)
        .and_then(|value| value.checked_div(5))
        .ok_or_else(|| TxRuleError::InvalidAtomicPayload("liquidity virtual token reserve overflow".to_string()))
}

fn atomic_op_allows_liquidity_vault_output(op: &AtomicPayloadOp) -> bool {
    matches!(
        op,
        AtomicPayloadOp::CreateLiquidityAsset { .. }
            | AtomicPayloadOp::BuyLiquidityExactIn { .. }
            | AtomicPayloadOp::SellLiquidityExactIn { .. }
            | AtomicPayloadOp::ClaimLiquidityFees { .. }
    )
}

fn liquidity_sell_locked(pool: &AtomicLiquidityPoolState) -> bool {
    pool.unlock_target_sompi > 0 && !pool.unlocked
}

fn validate_liquidity_unlock_target(unlock_target_sompi: u64) -> TxResult<()> {
    if unlock_target_sompi > MAX_SOMPI {
        Err(TxRuleError::InvalidAtomicPayload(format!(
            "liquidity unlock target `{unlock_target_sompi}` exceeds MAX_SOMPI `{MAX_SOMPI}`"
        )))
    } else {
        Ok(())
    }
}

fn validate_liquidity_claim_authorization(claimant_owner_id: [u8; 32], recipient_owner_id: [u8; 32]) -> TxResult<()> {
    if claimant_owner_id == recipient_owner_id {
        Ok(())
    } else {
        Err(TxRuleError::InvalidAtomicPayload("claim caller is not the configured liquidity fee recipient".to_string()))
    }
}

fn validate_liquidity_creation_parameters(decimals: u8, max_supply: u128, seed_reserve_sompi: u64) -> TxResult<()> {
    if decimals != LIQUIDITY_TOKEN_DECIMALS {
        return Err(TxRuleError::InvalidAtomicPayload(format!("liquidity asset decimals must be `{}`", LIQUIDITY_TOKEN_DECIMALS)));
    }
    if !(MIN_LIQUIDITY_SUPPLY_RAW..=MAX_LIQUIDITY_SUPPLY_RAW).contains(&max_supply) {
        return Err(TxRuleError::InvalidAtomicPayload(format!(
            "liquidity asset max_supply must be in `{MIN_LIQUIDITY_SUPPLY_RAW}..={MAX_LIQUIDITY_SUPPLY_RAW}`"
        )));
    }
    if seed_reserve_sompi != INITIAL_REAL_CPAY_RESERVES_SOMPI {
        return Err(TxRuleError::InvalidAtomicPayload(format!(
            "liquidity asset seed_reserve_sompi must be `{INITIAL_REAL_CPAY_RESERVES_SOMPI}`"
        )));
    }
    Ok(())
}

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
    ///     1. The block header includes the expected state commitment in `utxo_commitment`.
    ///     2. The block header includes the expected `accepted_id_merkle_root`.
    ///     3. The block coinbase transaction rewards the mergeset blocks correctly.
    ///     4. All non-coinbase block transactions are valid against its own UTXO view.
    pub(super) fn verify_expected_utxo_state<V: UtxoView + Sync>(
        &self,
        ctx: &mut UtxoProcessingContext,
        selected_parent_utxo_view: &V,
        header: &Header,
    ) -> BlockProcessResult<()> {
        // Verify header state commitment. Before the payload HF this is the raw UTXO commitment;
        // after the HF it commits to both UTXO and Atomic consensus state.
        let utxo_commitment = ctx.multiset_hash.finalize();
        let expected_commitment = ctx
            .atomic_state
            .header_commitment_for_state(utxo_commitment, self.transaction_validator.is_payload_hf_active(header.daa_score));
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
        let liquidity_vault_output_count = tx_ref
            .outputs
            .iter()
            .filter(|output| matches!(ScriptClass::from_script(&output.script_public_key), ScriptClass::LiquidityVault))
            .count();
        let spent_vault_inputs = self.collect_spent_liquidity_vault_inputs(tx, atomic_state)?;

        if !payload_hf_active || !tx_ref.subnetwork_id.is_payload() || tx_ref.payload.is_empty() {
            if !spent_vault_inputs.is_empty() || liquidity_vault_output_count > 0 {
                return Err(TxRuleError::InvalidAtomicPayload(
                    "reserved LiquidityVault scripts require a CAT liquidity payload".to_string(),
                ));
            }
            self.apply_anchor_deltas_to_atomic_state(tx, atomic_state);
            return Ok(());
        }

        let Some(parsed_payload) = parse_atomic_payload(tx_ref.payload.as_slice()).map_err(TxRuleError::InvalidAtomicPayload)? else {
            if !spent_vault_inputs.is_empty() || liquidity_vault_output_count > 0 {
                return Err(TxRuleError::InvalidAtomicPayload(
                    "reserved LiquidityVault scripts require a CAT liquidity payload".to_string(),
                ));
            }
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

        if !spent_vault_inputs.is_empty() {
            match &parsed_payload.op {
                AtomicPayloadOp::BuyLiquidityExactIn { .. }
                | AtomicPayloadOp::SellLiquidityExactIn { .. }
                | AtomicPayloadOp::ClaimLiquidityFees { .. } => {}
                _ => {
                    return Err(TxRuleError::InvalidAtomicPayload(
                        "spending a LiquidityVault input is only valid for buy/sell/claim liquidity ops".to_string(),
                    ))
                }
            }
        }
        if liquidity_vault_output_count > 0 && !atomic_op_allows_liquidity_vault_output(&parsed_payload.op) {
            return Err(TxRuleError::InvalidAtomicPayload(
                "creating a LiquidityVault output is only valid for create/buy/sell/claim liquidity ops".to_string(),
            ));
        }
        if matches!(parsed_payload.op, AtomicPayloadOp::CreateLiquidityAsset { .. }) && !spent_vault_inputs.is_empty() {
            return Err(TxRuleError::InvalidAtomicPayload("create-liquidity must not spend any LiquidityVault input".to_string()));
        }

        self.validate_replacement_anchor(tx, owner_id, atomic_state)?;
        self.apply_atomic_op_to_state(tx, tx.tx().id().as_bytes(), owner_id, parsed_payload.op, atomic_state)?;

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
        tx: &impl VerifiableTransaction,
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
                platform_tag,
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
                self.insert_atomic_asset_state(
                    atomic_state,
                    asset_id,
                    AtomicAssetState {
                        asset_class: AtomicAssetClass::Standard,
                        mint_authority_owner_id,
                        supply_mode,
                        max_supply,
                        total_supply: 0,
                        platform_tag,
                        liquidity: None,
                    },
                )?;
            }
            AtomicPayloadOp::CreateAssetWithMint {
                decimals: _,
                supply_mode,
                max_supply,
                mint_authority_owner_id,
                name: _,
                symbol: _,
                metadata: _,
                initial_mint_amount,
                initial_mint_to_owner_id,
                platform_tag,
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
                let mut total_supply = 0u128;
                if initial_mint_amount > 0 {
                    if matches!(supply_mode, AtomicSupplyMode::Capped) && initial_mint_amount > max_supply {
                        return Err(TxRuleError::InvalidAtomicPayload(format!(
                            "initial mint exceeds cap for asset `{}`",
                            faster_hex::hex_string(&asset_id)
                        )));
                    }
                    let receiver_key = AtomicBalanceKey { asset_id, owner_id: initial_mint_to_owner_id };
                    let receiver_balance = atomic_state.balances.get(&receiver_key).copied().unwrap_or(0);
                    let receiver_after = receiver_balance.checked_add(initial_mint_amount).ok_or_else(|| {
                        TxRuleError::InvalidAtomicPayload(format!(
                            "balance overflow while create-and-mint asset `{}`",
                            faster_hex::hex_string(&asset_id)
                        ))
                    })?;
                    atomic_state.balances.insert(receiver_key, receiver_after);
                    total_supply = initial_mint_amount;
                }
                self.insert_atomic_asset_state(
                    atomic_state,
                    asset_id,
                    AtomicAssetState {
                        asset_class: AtomicAssetClass::Standard,
                        mint_authority_owner_id,
                        supply_mode,
                        max_supply,
                        total_supply,
                        platform_tag,
                        liquidity: None,
                    },
                )?;
            }
            AtomicPayloadOp::CreateLiquidityAsset {
                decimals,
                max_supply,
                name: _,
                symbol: _,
                metadata: _,
                seed_reserve_sompi,
                fee_bps,
                recipients,
                launch_buy_sompi,
                launch_buy_min_token_out,
                platform_tag,
                liquidity_unlock_target_sompi,
            } => {
                let asset_id = tx_id_bytes;
                if atomic_state.assets.contains_key(&asset_id) {
                    return Err(TxRuleError::InvalidAtomicPayload(format!(
                        "asset `{}` already exists",
                        faster_hex::hex_string(&asset_id)
                    )));
                }
                validate_liquidity_creation_parameters(decimals, max_supply, seed_reserve_sompi)?;
                validate_liquidity_unlock_target(liquidity_unlock_target_sompi)?;
                let (vault_output_index, vault_output_value) = self.resolve_create_liquidity_vault_output(tx)?;
                let expected_vault_value = seed_reserve_sompi
                    .checked_add(launch_buy_sompi)
                    .ok_or_else(|| TxRuleError::InvalidAtomicPayload("vault value overflow on create".to_string()))?;
                if vault_output_value != expected_vault_value {
                    return Err(TxRuleError::InvalidAtomicPayload(format!(
                        "create liquidity vault output mismatch: expected `{expected_vault_value}`, got `{vault_output_value}`"
                    )));
                }

                let mut fee_recipients = self.build_fee_recipient_state(recipients)?;
                if fee_bps > 0 && fee_recipients.is_empty() {
                    return Err(TxRuleError::InvalidAtomicPayload("fee_bps > 0 requires at least one recipient".to_string()));
                }

                let mut real_cpay_reserves_sompi = INITIAL_REAL_CPAY_RESERVES_SOMPI;
                let mut real_token_reserves = max_supply;
                let mut virtual_cpay_reserves_sompi = INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI;
                let mut virtual_token_reserves = initial_virtual_token_reserves(max_supply)?;
                let mut unclaimed_fee_total_sompi = 0u64;
                let mut total_supply = 0u128;

                if launch_buy_sompi > 0 {
                    let fee_trade = calculate_trade_fee(launch_buy_sompi, fee_bps)?;
                    let launch_buy_net = launch_buy_sompi
                        .checked_sub(fee_trade)
                        .ok_or_else(|| TxRuleError::InvalidAtomicPayload("launch buy fee underflow".to_string()))?;
                    let (token_out, new_real_token_reserves, new_virtual_cpay_reserves_sompi, new_virtual_token_reserves) =
                        cpmm_buy(real_token_reserves, virtual_cpay_reserves_sompi, virtual_token_reserves, launch_buy_net)?;
                    if token_out < launch_buy_min_token_out {
                        return Err(TxRuleError::InvalidAtomicPayload(format!(
                            "launch buy min_token_out violated: expected at least `{}`, got `{}`",
                            launch_buy_min_token_out, token_out
                        )));
                    }
                    if token_out == 0 {
                        return Err(TxRuleError::InvalidAtomicPayload("launch buy produced zero token_out".to_string()));
                    }
                    real_cpay_reserves_sompi = real_cpay_reserves_sompi
                        .checked_add(launch_buy_net)
                        .ok_or_else(|| TxRuleError::InvalidAtomicPayload("launch buy real CPAY reserve overflow".to_string()))?;
                    real_token_reserves = new_real_token_reserves;
                    virtual_cpay_reserves_sompi = new_virtual_cpay_reserves_sompi;
                    virtual_token_reserves = new_virtual_token_reserves;
                    self.apply_fee_to_pool(&mut fee_recipients, &mut unclaimed_fee_total_sompi, fee_trade)?;
                    total_supply = token_out;

                    let receiver_key = AtomicBalanceKey { asset_id, owner_id };
                    let receiver_balance = atomic_state.balances.get(&receiver_key).copied().unwrap_or(0);
                    let receiver_after = receiver_balance.checked_add(token_out).ok_or_else(|| {
                        TxRuleError::InvalidAtomicPayload(format!(
                            "balance overflow while launch-buy minting liquidity asset `{}`",
                            faster_hex::hex_string(&asset_id)
                        ))
                    })?;
                    atomic_state.balances.insert(receiver_key, receiver_after);
                }

                let vault_outpoint = TransactionOutpoint::new(tx.tx().id(), vault_output_index);
                let unlocked = liquidity_unlock_target_sompi == 0 || real_cpay_reserves_sompi >= liquidity_unlock_target_sompi;
                let asset = AtomicAssetState {
                    asset_class: AtomicAssetClass::Liquidity,
                    mint_authority_owner_id: [0u8; 32],
                    supply_mode: AtomicSupplyMode::Capped,
                    max_supply,
                    total_supply,
                    platform_tag,
                    liquidity: Some(AtomicLiquidityPoolState {
                        pool_nonce: 1,
                        real_cpay_reserves_sompi,
                        real_token_reserves,
                        virtual_cpay_reserves_sompi,
                        virtual_token_reserves,
                        unclaimed_fee_total_sompi,
                        fee_bps,
                        fee_recipients,
                        vault_outpoint,
                        vault_value_sompi: vault_output_value,
                        unlock_target_sompi: liquidity_unlock_target_sompi,
                        unlocked,
                    }),
                };
                self.validate_liquidity_invariants(asset_id, &asset)?;
                self.insert_atomic_asset_state(atomic_state, asset_id, asset)?;
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
                if matches!(asset.asset_class, AtomicAssetClass::Liquidity) {
                    return Err(TxRuleError::InvalidAtomicPayload(format!(
                        "legacy mint is invalid for liquidity asset `{}`",
                        faster_hex::hex_string(&asset_id)
                    )));
                }
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
                self.insert_atomic_asset_state(atomic_state, asset_id, asset)?;
                atomic_state.balances.insert(receiver_key, receiver_after);
            }
            AtomicPayloadOp::Burn { asset_id, amount } => {
                let mut asset = atomic_state.assets.get(&asset_id).cloned().ok_or_else(|| {
                    TxRuleError::InvalidAtomicPayload(format!("burn references unknown asset `{}`", faster_hex::hex_string(&asset_id)))
                })?;
                if matches!(asset.asset_class, AtomicAssetClass::Liquidity) {
                    return Err(TxRuleError::InvalidAtomicPayload(format!(
                        "legacy burn is invalid for liquidity asset `{}`",
                        faster_hex::hex_string(&asset_id)
                    )));
                }
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
                self.insert_atomic_asset_state(atomic_state, asset_id, asset)?;
                if sender_after == 0 {
                    atomic_state.balances.remove(&sender_key);
                } else {
                    atomic_state.balances.insert(sender_key, sender_after);
                }
            }
            AtomicPayloadOp::BuyLiquidityExactIn { asset_id, expected_pool_nonce, cpay_in_sompi, min_token_out } => {
                let mut asset = atomic_state.assets.get(&asset_id).cloned().ok_or_else(|| {
                    TxRuleError::InvalidAtomicPayload(format!("buy references unknown asset `{}`", faster_hex::hex_string(&asset_id)))
                })?;
                if !matches!(asset.asset_class, AtomicAssetClass::Liquidity) {
                    return Err(TxRuleError::InvalidAtomicPayload(format!(
                        "buy is only valid for liquidity assets (`{}` is standard)",
                        faster_hex::hex_string(&asset_id)
                    )));
                }
                let mut pool = asset.liquidity.clone().ok_or_else(|| {
                    TxRuleError::InvalidAtomicPayload(format!(
                        "liquidity state missing for asset `{}`",
                        faster_hex::hex_string(&asset_id)
                    ))
                })?;
                if pool.pool_nonce != expected_pool_nonce {
                    return Err(TxRuleError::InvalidAtomicPayload(format!(
                        "stale liquidity nonce for asset `{}`: expected `{}`, got `{}`",
                        faster_hex::hex_string(&asset_id),
                        pool.pool_nonce,
                        expected_pool_nonce
                    )));
                }

                let vault_transition = self.resolve_liquidity_vault_transition(tx, pool.vault_outpoint)?;
                let vault_delta = vault_transition
                    .output_value
                    .checked_sub(vault_transition.input_value)
                    .ok_or_else(|| TxRuleError::InvalidAtomicPayload("buy requires vault_value to increase".to_string()))?;
                if vault_delta != cpay_in_sompi {
                    return Err(TxRuleError::InvalidAtomicPayload(format!(
                        "buy vault delta mismatch: expected `{}`, got `{}`",
                        cpay_in_sompi, vault_delta
                    )));
                }

                let fee_trade = calculate_trade_fee(cpay_in_sompi, pool.fee_bps)?;
                let net_in = cpay_in_sompi
                    .checked_sub(fee_trade)
                    .ok_or_else(|| TxRuleError::InvalidAtomicPayload("buy fee underflow".to_string()))?;
                let (token_out, new_real_token_reserves, new_virtual_cpay_reserves_sompi, new_virtual_token_reserves) =
                    cpmm_buy(pool.real_token_reserves, pool.virtual_cpay_reserves_sompi, pool.virtual_token_reserves, net_in)?;
                if token_out < min_token_out {
                    return Err(TxRuleError::InvalidAtomicPayload(format!(
                        "buy min_token_out violated: expected at least `{}`, got `{}`",
                        min_token_out, token_out
                    )));
                }
                if token_out == 0 {
                    return Err(TxRuleError::InvalidAtomicPayload("buy produced zero token_out".to_string()));
                }

                pool.real_cpay_reserves_sompi = pool
                    .real_cpay_reserves_sompi
                    .checked_add(net_in)
                    .ok_or_else(|| TxRuleError::InvalidAtomicPayload("buy real CPAY reserve overflow".to_string()))?;
                pool.real_token_reserves = new_real_token_reserves;
                pool.virtual_cpay_reserves_sompi = new_virtual_cpay_reserves_sompi;
                pool.virtual_token_reserves = new_virtual_token_reserves;
                if pool.unlock_target_sompi > 0 && pool.real_cpay_reserves_sompi >= pool.unlock_target_sompi {
                    pool.unlocked = true;
                }
                self.apply_fee_to_pool(&mut pool.fee_recipients, &mut pool.unclaimed_fee_total_sompi, fee_trade)?;
                pool.vault_outpoint = TransactionOutpoint::new(tx.tx().id(), vault_transition.output_index);
                pool.vault_value_sompi = vault_transition.output_value;
                pool.pool_nonce = pool
                    .pool_nonce
                    .checked_add(1)
                    .ok_or_else(|| TxRuleError::InvalidAtomicPayload("pool nonce overflow".to_string()))?;

                let receiver_key = AtomicBalanceKey { asset_id, owner_id };
                let receiver_balance = atomic_state.balances.get(&receiver_key).copied().unwrap_or(0);
                let receiver_after = receiver_balance.checked_add(token_out).ok_or_else(|| {
                    TxRuleError::InvalidAtomicPayload(format!(
                        "receiver balance overflow while buying liquidity asset `{}`",
                        faster_hex::hex_string(&asset_id)
                    ))
                })?;
                atomic_state.balances.insert(receiver_key, receiver_after);
                asset.total_supply = asset.total_supply.checked_add(token_out).ok_or_else(|| {
                    TxRuleError::InvalidAtomicPayload(format!(
                        "total_supply overflow while buying liquidity asset `{}`",
                        faster_hex::hex_string(&asset_id)
                    ))
                })?;
                asset.liquidity = Some(pool);
                self.validate_liquidity_invariants(asset_id, &asset)?;
                self.insert_atomic_asset_state(atomic_state, asset_id, asset)?;
            }
            AtomicPayloadOp::SellLiquidityExactIn {
                asset_id,
                expected_pool_nonce,
                token_in,
                min_cpay_out_sompi,
                cpay_receive_output_index,
            } => {
                let mut asset = atomic_state.assets.get(&asset_id).cloned().ok_or_else(|| {
                    TxRuleError::InvalidAtomicPayload(format!("sell references unknown asset `{}`", faster_hex::hex_string(&asset_id)))
                })?;
                if !matches!(asset.asset_class, AtomicAssetClass::Liquidity) {
                    return Err(TxRuleError::InvalidAtomicPayload(format!(
                        "sell is only valid for liquidity assets (`{}` is standard)",
                        faster_hex::hex_string(&asset_id)
                    )));
                }
                let mut pool = asset.liquidity.clone().ok_or_else(|| {
                    TxRuleError::InvalidAtomicPayload(format!(
                        "liquidity state missing for asset `{}`",
                        faster_hex::hex_string(&asset_id)
                    ))
                })?;
                if pool.pool_nonce != expected_pool_nonce {
                    return Err(TxRuleError::InvalidAtomicPayload(format!(
                        "stale liquidity nonce for asset `{}`: expected `{}`, got `{}`",
                        faster_hex::hex_string(&asset_id),
                        pool.pool_nonce,
                        expected_pool_nonce
                    )));
                }
                if liquidity_sell_locked(&pool) {
                    return Err(TxRuleError::InvalidAtomicPayload(format!(
                        "liquidity sell locked for asset `{}` until real CPAY reserve reaches `{}` sompi",
                        faster_hex::hex_string(&asset_id),
                        pool.unlock_target_sompi
                    )));
                }
                let sender_key = AtomicBalanceKey { asset_id, owner_id };
                let sender_balance = atomic_state.balances.get(&sender_key).copied().unwrap_or(0);
                let sender_after = sender_balance.checked_sub(token_in).ok_or_else(|| {
                    TxRuleError::InvalidAtomicPayload(format!(
                        "insufficient balance for sell in liquidity asset `{}`",
                        faster_hex::hex_string(&asset_id)
                    ))
                })?;
                let supply_after = asset.total_supply.checked_sub(token_in).ok_or_else(|| {
                    TxRuleError::InvalidAtomicPayload(format!(
                        "total_supply underflow while selling liquidity asset `{}`",
                        faster_hex::hex_string(&asset_id)
                    ))
                })?;

                let (gross_out, new_real_cpay_reserves_sompi, new_virtual_cpay_reserves_sompi, new_virtual_token_reserves) =
                    cpmm_sell(pool.real_cpay_reserves_sompi, pool.virtual_cpay_reserves_sompi, pool.virtual_token_reserves, token_in)?;
                let fee_trade = calculate_trade_fee(gross_out, pool.fee_bps)?;
                let cpay_out = gross_out
                    .checked_sub(fee_trade)
                    .ok_or_else(|| TxRuleError::InvalidAtomicPayload("sell fee underflow".to_string()))?;
                if cpay_out == 0 {
                    return Err(TxRuleError::InvalidAtomicPayload("sell produced zero cpay_out".to_string()));
                }
                if cpay_out < min_cpay_out_sompi {
                    return Err(TxRuleError::InvalidAtomicPayload(format!(
                        "sell min_cpay_out violated: expected at least `{}`, got `{}`",
                        min_cpay_out_sompi, cpay_out
                    )));
                }
                if cpay_out < LIQUIDITY_MIN_PAYOUT_SOMPI {
                    return Err(TxRuleError::InvalidAtomicPayload(format!(
                        "sell payout `{}` below liquidity_min_payout_sompi `{}`",
                        cpay_out, LIQUIDITY_MIN_PAYOUT_SOMPI
                    )));
                }
                self.validate_payout_output(tx, cpay_receive_output_index, cpay_out, None)?;
                let vault_transition = self.resolve_liquidity_vault_transition(tx, pool.vault_outpoint)?;
                let vault_delta = vault_transition
                    .input_value
                    .checked_sub(vault_transition.output_value)
                    .ok_or_else(|| TxRuleError::InvalidAtomicPayload("sell requires vault_value to decrease".to_string()))?;
                if vault_delta != cpay_out {
                    return Err(TxRuleError::InvalidAtomicPayload(format!(
                        "sell vault delta mismatch: expected `{}`, got `{}`",
                        cpay_out, vault_delta
                    )));
                }

                pool.real_cpay_reserves_sompi = new_real_cpay_reserves_sompi;
                pool.real_token_reserves = pool
                    .real_token_reserves
                    .checked_add(token_in)
                    .ok_or_else(|| TxRuleError::InvalidAtomicPayload("sell real token reserve overflow".to_string()))?;
                pool.virtual_cpay_reserves_sompi = new_virtual_cpay_reserves_sompi;
                pool.virtual_token_reserves = new_virtual_token_reserves;
                self.apply_fee_to_pool(&mut pool.fee_recipients, &mut pool.unclaimed_fee_total_sompi, fee_trade)?;
                pool.vault_outpoint = TransactionOutpoint::new(tx.tx().id(), vault_transition.output_index);
                pool.vault_value_sompi = vault_transition.output_value;
                pool.pool_nonce = pool
                    .pool_nonce
                    .checked_add(1)
                    .ok_or_else(|| TxRuleError::InvalidAtomicPayload("pool nonce overflow".to_string()))?;

                if sender_after == 0 {
                    atomic_state.balances.remove(&sender_key);
                } else {
                    atomic_state.balances.insert(sender_key, sender_after);
                }

                asset.total_supply = supply_after;
                asset.liquidity = Some(pool);
                self.validate_liquidity_invariants(asset_id, &asset)?;
                self.insert_atomic_asset_state(atomic_state, asset_id, asset)?;
            }
            AtomicPayloadOp::ClaimLiquidityFees {
                asset_id,
                expected_pool_nonce,
                recipient_index,
                claim_amount_sompi,
                claim_receive_output_index,
            } => {
                let mut asset = atomic_state.assets.get(&asset_id).cloned().ok_or_else(|| {
                    TxRuleError::InvalidAtomicPayload(format!(
                        "claim references unknown asset `{}`",
                        faster_hex::hex_string(&asset_id)
                    ))
                })?;
                if !matches!(asset.asset_class, AtomicAssetClass::Liquidity) {
                    return Err(TxRuleError::InvalidAtomicPayload(format!(
                        "claim is only valid for liquidity assets (`{}` is standard)",
                        faster_hex::hex_string(&asset_id)
                    )));
                }
                let mut pool = asset.liquidity.clone().ok_or_else(|| {
                    TxRuleError::InvalidAtomicPayload(format!(
                        "liquidity state missing for asset `{}`",
                        faster_hex::hex_string(&asset_id)
                    ))
                })?;
                if pool.pool_nonce != expected_pool_nonce {
                    return Err(TxRuleError::InvalidAtomicPayload(format!(
                        "stale liquidity nonce for asset `{}`: expected `{}`, got `{}`",
                        faster_hex::hex_string(&asset_id),
                        pool.pool_nonce,
                        expected_pool_nonce
                    )));
                }
                if liquidity_sell_locked(&pool) {
                    return Err(TxRuleError::InvalidAtomicPayload(format!(
                        "liquidity fee claim locked for asset `{}` until curve reserve reaches `{}` sompi",
                        faster_hex::hex_string(&asset_id),
                        pool.unlock_target_sompi
                    )));
                }
                if claim_amount_sompi < LIQUIDITY_MIN_PAYOUT_SOMPI {
                    return Err(TxRuleError::InvalidAtomicPayload(format!(
                        "claim amount `{}` below liquidity_min_payout_sompi `{}`",
                        claim_amount_sompi, LIQUIDITY_MIN_PAYOUT_SOMPI
                    )));
                }
                let recipient_index = usize::from(recipient_index);
                if recipient_index >= pool.fee_recipients.len() {
                    return Err(TxRuleError::InvalidAtomicPayload(format!("claim recipient_index `{recipient_index}` out of range")));
                }
                let recipient_owner_id = pool.fee_recipients[recipient_index].owner_id;
                let recipient_unclaimed = pool.fee_recipients[recipient_index].unclaimed_sompi;
                if recipient_unclaimed < claim_amount_sompi {
                    return Err(TxRuleError::InvalidAtomicPayload(format!(
                        "claim amount `{}` exceeds unclaimed recipient fees `{}`",
                        claim_amount_sompi, recipient_unclaimed
                    )));
                }
                validate_liquidity_claim_authorization(owner_id, recipient_owner_id)?;

                self.validate_payout_output(tx, claim_receive_output_index, claim_amount_sompi, Some(recipient_owner_id))?;
                let vault_transition = self.resolve_liquidity_vault_transition(tx, pool.vault_outpoint)?;
                let vault_delta = vault_transition
                    .input_value
                    .checked_sub(vault_transition.output_value)
                    .ok_or_else(|| TxRuleError::InvalidAtomicPayload("claim requires vault_value to decrease".to_string()))?;
                if vault_delta != claim_amount_sompi {
                    return Err(TxRuleError::InvalidAtomicPayload(format!(
                        "claim vault delta mismatch: expected `{}`, got `{}`",
                        claim_amount_sompi, vault_delta
                    )));
                }

                pool.fee_recipients[recipient_index].unclaimed_sompi = recipient_unclaimed - claim_amount_sompi;
                pool.unclaimed_fee_total_sompi = pool
                    .unclaimed_fee_total_sompi
                    .checked_sub(claim_amount_sompi)
                    .ok_or_else(|| TxRuleError::InvalidAtomicPayload("claim unclaimed_fee_total underflow".to_string()))?;
                pool.vault_outpoint = TransactionOutpoint::new(tx.tx().id(), vault_transition.output_index);
                pool.vault_value_sompi = vault_transition.output_value;
                pool.pool_nonce = pool
                    .pool_nonce
                    .checked_add(1)
                    .ok_or_else(|| TxRuleError::InvalidAtomicPayload("pool nonce overflow".to_string()))?;

                asset.liquidity = Some(pool);
                self.validate_liquidity_invariants(asset_id, &asset)?;
                self.insert_atomic_asset_state(atomic_state, asset_id, asset)?;
            }
        }
        Ok(())
    }

    fn insert_atomic_asset_state(
        &self,
        atomic_state: &mut AtomicConsensusState,
        asset_id: [u8; 32],
        asset: AtomicAssetState,
    ) -> TxResult<()> {
        if let Some(previous_asset) = atomic_state.assets.insert(asset_id, asset.clone()) {
            if let Some(previous_pool) = previous_asset.liquidity.as_ref() {
                atomic_state.liquidity_vault_outpoints.remove(&previous_pool.vault_outpoint);
            }
        }

        if matches!(asset.asset_class, AtomicAssetClass::Liquidity) {
            let pool = asset.liquidity.as_ref().ok_or_else(|| {
                TxRuleError::InvalidAtomicPayload(format!("liquidity state missing for asset `{}`", faster_hex::hex_string(&asset_id)))
            })?;
            if let Some(previous_asset_id) = atomic_state.liquidity_vault_outpoints.insert(pool.vault_outpoint, asset_id) {
                if previous_asset_id != asset_id {
                    return Err(TxRuleError::InvalidAtomicPayload(format!(
                        "multiple liquidity assets share vault outpoint `{}`",
                        pool.vault_outpoint
                    )));
                }
            }
        }

        Ok(())
    }

    fn collect_spent_liquidity_vault_inputs(
        &self,
        tx: &impl VerifiableTransaction,
        atomic_state: &AtomicConsensusState,
    ) -> TxResult<Vec<([u8; 32], TransactionOutpoint)>> {
        let mut spent = Vec::new();
        for (input, entry) in tx.populated_inputs() {
            if !matches!(ScriptClass::from_script(&entry.script_public_key), ScriptClass::LiquidityVault) {
                continue;
            }
            let Some(asset_id) = self.find_liquidity_asset_by_vault_outpoint(atomic_state, input.previous_outpoint)? else {
                return Err(TxRuleError::InvalidAtomicPayload(format!(
                    "unknown LiquidityVault input outpoint `{}`",
                    input.previous_outpoint,
                )));
            };
            spent.push((asset_id, input.previous_outpoint));
        }
        Ok(spent)
    }

    fn find_liquidity_asset_by_vault_outpoint(
        &self,
        atomic_state: &AtomicConsensusState,
        outpoint: TransactionOutpoint,
    ) -> TxResult<Option<[u8; 32]>> {
        if let Some(asset_id) = atomic_state.liquidity_vault_outpoints.get(&outpoint).copied() {
            let asset = atomic_state.assets.get(&asset_id).ok_or_else(|| {
                TxRuleError::InvalidAtomicPayload(format!(
                    "liquidity vault index references missing asset `{}`",
                    faster_hex::hex_string(&asset_id)
                ))
            })?;
            let pool = asset.liquidity.as_ref().ok_or_else(|| {
                TxRuleError::InvalidAtomicPayload(format!(
                    "liquidity vault index references asset `{}` without liquidity state",
                    faster_hex::hex_string(&asset_id)
                ))
            })?;
            if !matches!(asset.asset_class, AtomicAssetClass::Liquidity) || pool.vault_outpoint != outpoint {
                return Err(TxRuleError::InvalidAtomicPayload(format!("liquidity vault index mismatch for outpoint `{}`", outpoint)));
            }
            return Ok(Some(asset_id));
        }

        let mut matched = None;
        for (asset_id, asset) in atomic_state.assets.iter() {
            let Some(pool) = asset.liquidity.as_ref() else {
                continue;
            };
            if !matches!(asset.asset_class, AtomicAssetClass::Liquidity) || pool.vault_outpoint != outpoint {
                continue;
            }
            if matched.replace(*asset_id).is_some() {
                return Err(TxRuleError::InvalidAtomicPayload(format!(
                    "multiple liquidity assets share vault outpoint `{}`",
                    outpoint
                )));
            }
        }
        Ok(matched)
    }

    fn resolve_create_liquidity_vault_output(&self, tx: &impl VerifiableTransaction) -> TxResult<(u32, u64)> {
        for (_, entry) in tx.populated_inputs() {
            if matches!(ScriptClass::from_script(&entry.script_public_key), ScriptClass::LiquidityVault) {
                return Err(TxRuleError::InvalidAtomicPayload("create-liquidity must not spend any LiquidityVault input".to_string()));
            }
        }

        let mut found: Option<(u32, u64)> = None;
        for (index, output) in tx.tx().outputs.iter().enumerate() {
            if !matches!(ScriptClass::from_script(&output.script_public_key), ScriptClass::LiquidityVault) {
                continue;
            }
            let out_index =
                u32::try_from(index).map_err(|_| TxRuleError::InvalidAtomicPayload("vault output index overflow".to_string()))?;
            if found.is_some() {
                return Err(TxRuleError::InvalidAtomicPayload(
                    "create-liquidity must have exactly one LiquidityVault output".to_string(),
                ));
            }
            found = Some((out_index, output.value));
        }
        found.ok_or_else(|| {
            TxRuleError::InvalidAtomicPayload("create-liquidity must have exactly one LiquidityVault output".to_string())
        })
    }

    fn resolve_liquidity_vault_transition(
        &self,
        tx: &impl VerifiableTransaction,
        expected_vault_outpoint: TransactionOutpoint,
    ) -> TxResult<VaultTransition> {
        let mut input_value = None;
        for (input, entry) in tx.populated_inputs() {
            if !matches!(ScriptClass::from_script(&entry.script_public_key), ScriptClass::LiquidityVault) {
                continue;
            }
            if input_value.is_some() {
                return Err(TxRuleError::InvalidAtomicPayload(
                    "liquidity transition must have exactly one LiquidityVault input".to_string(),
                ));
            }
            if input.previous_outpoint != expected_vault_outpoint {
                return Err(TxRuleError::InvalidAtomicPayload(format!(
                    "liquidity vault outpoint mismatch: expected `{}`, got `{}`",
                    expected_vault_outpoint, input.previous_outpoint
                )));
            }
            input_value = Some(entry.amount);
        }
        let input_value = input_value.ok_or_else(|| {
            TxRuleError::InvalidAtomicPayload("liquidity transition must have exactly one LiquidityVault input".to_string())
        })?;

        let mut output = None;
        for (index, tx_output) in tx.tx().outputs.iter().enumerate() {
            if !matches!(ScriptClass::from_script(&tx_output.script_public_key), ScriptClass::LiquidityVault) {
                continue;
            }
            if output.is_some() {
                return Err(TxRuleError::InvalidAtomicPayload(
                    "liquidity transition must have exactly one LiquidityVault output".to_string(),
                ));
            }
            let out_index =
                u32::try_from(index).map_err(|_| TxRuleError::InvalidAtomicPayload("vault output index overflow".to_string()))?;
            output = Some((out_index, tx_output.value));
        }
        let (output_index, output_value) = output.ok_or_else(|| {
            TxRuleError::InvalidAtomicPayload("liquidity transition must have exactly one LiquidityVault output".to_string())
        })?;

        Ok(VaultTransition { input_value, output_index, output_value })
    }

    fn build_fee_recipient_state(
        &self,
        recipients: Vec<AtomicPayloadRecipientAddress>,
    ) -> TxResult<Vec<AtomicLiquidityFeeRecipientState>> {
        let mut out = Vec::with_capacity(recipients.len());
        for recipient in recipients {
            let owner_id = atomic_owner_id_from_address_components(recipient.address_version, &recipient.address_payload)
                .ok_or_else(|| TxRuleError::InvalidAtomicPayload("invalid liquidity fee recipient address encoding".to_string()))?;
            out.push(AtomicLiquidityFeeRecipientState {
                owner_id,
                address_version: recipient.address_version,
                address_payload: recipient.address_payload,
                unclaimed_sompi: 0,
            });
        }
        Ok(out)
    }

    fn apply_fee_to_pool(
        &self,
        recipients: &mut [AtomicLiquidityFeeRecipientState],
        unclaimed_fee_total_sompi: &mut u64,
        fee_trade: u64,
    ) -> TxResult<()> {
        if fee_trade == 0 {
            return Ok(());
        }
        *unclaimed_fee_total_sompi = unclaimed_fee_total_sompi
            .checked_add(fee_trade)
            .ok_or_else(|| TxRuleError::InvalidAtomicPayload("unclaimed_fee_total overflow".to_string()))?;
        match recipients.len() {
            0 => Err(TxRuleError::InvalidAtomicPayload("fee_trade > 0 but no fee recipients are configured".to_string())),
            1 => {
                recipients[0].unclaimed_sompi = recipients[0]
                    .unclaimed_sompi
                    .checked_add(fee_trade)
                    .ok_or_else(|| TxRuleError::InvalidAtomicPayload("recipient fee overflow".to_string()))?;
                Ok(())
            }
            2 => {
                let fee0 = fee_trade / 2;
                let fee1 = fee_trade - fee0;
                recipients[0].unclaimed_sompi = recipients[0]
                    .unclaimed_sompi
                    .checked_add(fee0)
                    .ok_or_else(|| TxRuleError::InvalidAtomicPayload("recipient0 fee overflow".to_string()))?;
                recipients[1].unclaimed_sompi = recipients[1]
                    .unclaimed_sompi
                    .checked_add(fee1)
                    .ok_or_else(|| TxRuleError::InvalidAtomicPayload("recipient1 fee overflow".to_string()))?;
                Ok(())
            }
            _ => Err(TxRuleError::InvalidAtomicPayload("invalid recipient count in liquidity pool state".to_string())),
        }
    }

    fn validate_liquidity_invariants(&self, asset_id: [u8; 32], asset: &AtomicAssetState) -> TxResult<()> {
        if !matches!(asset.asset_class, AtomicAssetClass::Liquidity) {
            return Ok(());
        }
        let pool = asset.liquidity.as_ref().ok_or_else(|| {
            TxRuleError::InvalidAtomicPayload(format!("liquidity state missing for asset `{}`", faster_hex::hex_string(&asset_id)))
        })?;
        if !matches!(asset.supply_mode, AtomicSupplyMode::Capped) {
            return Err(TxRuleError::InvalidAtomicPayload("liquidity assets must always use capped supply mode".to_string()));
        }
        validate_liquidity_unlock_target(pool.unlock_target_sompi)?;
        if pool.unlock_target_sompi == 0 && !pool.unlocked {
            return Err(TxRuleError::InvalidAtomicPayload("liquidity lock disabled pools must be marked unlocked".to_string()));
        }
        if pool.unlock_target_sompi > 0 && pool.real_cpay_reserves_sompi >= pool.unlock_target_sompi && !pool.unlocked {
            return Err(TxRuleError::InvalidAtomicPayload(format!(
                "liquidity lock target reached for asset `{}` but pool is still locked",
                faster_hex::hex_string(&asset_id)
            )));
        }
        if pool.real_cpay_reserves_sompi < MIN_CPAY_RESERVE_SOMPI {
            return Err(TxRuleError::InvalidAtomicPayload(format!(
                "real CPAY reserve floor violation for asset `{}`",
                faster_hex::hex_string(&asset_id)
            )));
        }
        if pool.real_token_reserves < MIN_REAL_TOKEN_RESERVE {
            return Err(TxRuleError::InvalidAtomicPayload(format!(
                "real token reserve floor violation for asset `{}`",
                faster_hex::hex_string(&asset_id)
            )));
        }
        if pool.virtual_cpay_reserves_sompi == 0 || pool.virtual_token_reserves == 0 {
            return Err(TxRuleError::InvalidAtomicPayload(format!(
                "virtual reserve invariant violation for asset `{}`",
                faster_hex::hex_string(&asset_id)
            )));
        }
        let expected_vault = pool
            .real_cpay_reserves_sompi
            .checked_add(pool.unclaimed_fee_total_sompi)
            .ok_or_else(|| TxRuleError::InvalidAtomicPayload("vault invariant overflow".to_string()))?;
        if pool.vault_value_sompi != expected_vault {
            return Err(TxRuleError::InvalidAtomicPayload(format!(
                "vault invariant violation for asset `{}`: vault_value `{}` != real reserve `{}` + fees `{}`",
                faster_hex::hex_string(&asset_id),
                pool.vault_value_sompi,
                pool.real_cpay_reserves_sompi,
                pool.unclaimed_fee_total_sompi
            )));
        }
        let expected_total = asset
            .total_supply
            .checked_add(pool.real_token_reserves)
            .ok_or_else(|| TxRuleError::InvalidAtomicPayload("supply invariant overflow".to_string()))?;
        if expected_total != asset.max_supply {
            return Err(TxRuleError::InvalidAtomicPayload(format!(
                "supply invariant violation for asset `{}`: circulating `{}` + real token reserves `{}` != max `{}`",
                faster_hex::hex_string(&asset_id),
                asset.total_supply,
                pool.real_token_reserves,
                asset.max_supply
            )));
        }
        Ok(())
    }

    fn validate_payout_output(
        &self,
        tx: &impl VerifiableTransaction,
        output_index: u16,
        expected_value: u64,
        expected_owner_id: Option<[u8; 32]>,
    ) -> TxResult<()> {
        let output = tx
            .tx()
            .outputs
            .get(output_index as usize)
            .ok_or_else(|| TxRuleError::InvalidAtomicPayload(format!("payout output index `{}` out of range", output_index)))?;
        if output.value != expected_value {
            return Err(TxRuleError::InvalidAtomicPayload(format!(
                "payout output value mismatch at index `{}`: expected `{}`, got `{}`",
                output_index, expected_value, output.value
            )));
        }
        let class = ScriptClass::from_script(&output.script_public_key);
        if !matches!(class, ScriptClass::PubKey | ScriptClass::PubKeyECDSA | ScriptClass::ScriptHash) {
            return Err(TxRuleError::InvalidAtomicPayload(format!(
                "payout script class `{}` at index `{}` is not allowed",
                class, output_index
            )));
        }
        if let Some(owner_id) = expected_owner_id {
            let output_owner_id = atomic_owner_id_from_script(&output.script_public_key)
                .ok_or_else(|| TxRuleError::InvalidAtomicPayload("payout output owner id cannot be derived".to_string()))?;
            if output_owner_id != owner_id {
                return Err(TxRuleError::InvalidAtomicPayload(
                    "payout output owner does not match configured fee recipient".to_string(),
                ));
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
