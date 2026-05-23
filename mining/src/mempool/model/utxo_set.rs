use std::collections::HashSet;

use crate::{
    mempool::{
        errors::RuleResult,
        model::{map::OutpointIndex, tx::DoubleSpend},
    },
    model::TransactionIdSet,
};
use cryptix_consensus_core::{
    constants::UNACCEPTED_DAA_SCORE,
    tx::{MutableTransaction, TransactionId, TransactionOutpoint, UtxoEntry},
    utxo::utxo_collection::UtxoCollection,
};

pub(crate) struct MempoolUtxoSet {
    pool_unspent_outputs: UtxoCollection,
    outpoint_owner_id: OutpointIndex,
}

impl MempoolUtxoSet {
    pub(crate) fn new() -> Self {
        Self { pool_unspent_outputs: UtxoCollection::default(), outpoint_owner_id: OutpointIndex::default() }
    }

    pub(crate) fn add_transaction(&mut self, transaction: &MutableTransaction) {
        let transaction_id = transaction.id();
        let mut outpoint = TransactionOutpoint::new(transaction_id, 0);

        for (i, input) in transaction.tx.inputs.iter().enumerate() {
            outpoint.index = i as u32;

            // Delete the output this input spends, in case it was created by mempool.
            // If the outpoint doesn't exist in self.pool_unspent_outputs - this means
            // it was created in the DAG (a.k.a. in consensus).
            self.pool_unspent_outputs.remove(&input.previous_outpoint);

            self.outpoint_owner_id.insert(input.previous_outpoint, transaction_id);
        }

        for (i, output) in transaction.tx.outputs.iter().enumerate() {
            let outpoint = TransactionOutpoint::new(transaction_id, i as u32);
            let entry = UtxoEntry::new(output.value, output.script_public_key.clone(), UNACCEPTED_DAA_SCORE, false);
            self.pool_unspent_outputs.insert(outpoint, entry);
        }
    }

    pub(crate) fn remove_transaction(&mut self, transaction: &MutableTransaction, parent_ids_in_pool: &TransactionIdSet) {
        let transaction_id = transaction.id();
        // We cannot assume here that the transaction is fully populated.
        // Notably, this is not the case when revalidate_transaction fails and leads the execution path here.
        for (i, input) in transaction.tx.inputs.iter().enumerate() {
            if let Some(ref entry) = transaction.entries[i] {
                // If the transaction creating the output spent by this input is in the mempool - restore it's UTXO
                if parent_ids_in_pool.contains(&input.previous_outpoint.transaction_id) {
                    self.pool_unspent_outputs.insert(input.previous_outpoint, entry.clone());
                }
            }
            self.outpoint_owner_id.remove(&input.previous_outpoint);
        }

        let mut outpoint = TransactionOutpoint::new(transaction_id, 0);
        for i in 0..transaction.tx.outputs.len() {
            outpoint.index = i as u32;
            self.pool_unspent_outputs.remove(&outpoint);
        }
    }

    pub(crate) fn get_outpoint_owner_id(&self, outpoint: &TransactionOutpoint) -> Option<&TransactionId> {
        self.outpoint_owner_id.get(outpoint)
    }

    /// Make sure no other transaction in the mempool is already spending an output which one of this transaction inputs spends
    pub(crate) fn check_double_spends(&self, transaction: &MutableTransaction) -> RuleResult<()> {
        match self.get_first_double_spend(transaction) {
            Some(double_spend) => Err(double_spend.into()),
            None => Ok(()),
        }
    }

    pub(crate) fn get_first_double_spend(&self, transaction: &MutableTransaction) -> Option<DoubleSpend> {
        let transaction_id = transaction.id();
        for input in transaction.tx.inputs.iter() {
            if let Some(existing_transaction_id) = self.get_outpoint_owner_id(&input.previous_outpoint) {
                if *existing_transaction_id != transaction_id {
                    return Some(DoubleSpend::new(input.previous_outpoint, *existing_transaction_id));
                }
            }
        }
        None
    }

    /// Returns the first double spend of every transaction in the mempool double spending on `transaction`
    pub(crate) fn get_double_spend_transaction_ids(&self, transaction: &MutableTransaction) -> Vec<DoubleSpend> {
        let transaction_id = transaction.id();
        let mut double_spends = vec![];
        let mut visited = HashSet::new();
        for input in transaction.tx.inputs.iter() {
            if let Some(existing_transaction_id) = self.get_outpoint_owner_id(&input.previous_outpoint) {
                if *existing_transaction_id != transaction_id && visited.insert(*existing_transaction_id) {
                    double_spends.push(DoubleSpend::new(input.previous_outpoint, *existing_transaction_id));
                }
            }
        }
        double_spends
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptix_consensus_core::{
        constants::TX_VERSION,
        subnets::SUBNETWORK_ID_NATIVE,
        tx::{scriptvec, ScriptPublicKey, Transaction, TransactionInput, TransactionOutput},
    };
    use std::sync::Arc;

    fn script_public_key() -> ScriptPublicKey {
        ScriptPublicKey::new(0, scriptvec![0x51])
    }

    fn entry(amount: u64) -> UtxoEntry {
        UtxoEntry::new(amount, script_public_key(), 0, false)
    }

    fn tx_spending(previous_outpoint: TransactionOutpoint, amount: u64) -> Arc<Transaction> {
        Arc::new(Transaction::new(
            TX_VERSION,
            vec![TransactionInput::new(previous_outpoint, vec![], 0, 0)],
            vec![TransactionOutput::new(amount, script_public_key())],
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            vec![],
        ))
    }

    #[test]
    fn adding_child_removes_spent_parent_output_from_mempool_utxo_set() {
        let mut utxo_set = MempoolUtxoSet::new();
        let parent_input = TransactionOutpoint::new(TransactionId::from_u64_word(1), 0);
        let parent_tx = tx_spending(parent_input, 10);
        let parent_outpoint = TransactionOutpoint::new(parent_tx.id(), 0);
        let parent = MutableTransaction {
            tx: parent_tx,
            entries: vec![Some(entry(11))],
            calculated_fee: Some(1),
            calculated_compute_mass: Some(1),
        };

        utxo_set.add_transaction(&parent);
        assert!(utxo_set.pool_unspent_outputs.contains_key(&parent_outpoint));

        let child_tx = tx_spending(parent_outpoint, 9);
        let child_outpoint = TransactionOutpoint::new(child_tx.id(), 0);
        let child = MutableTransaction {
            tx: child_tx,
            entries: vec![Some(entry(10))],
            calculated_fee: Some(1),
            calculated_compute_mass: Some(1),
        };

        utxo_set.add_transaction(&child);

        assert!(
            !utxo_set.pool_unspent_outputs.contains_key(&parent_outpoint),
            "a mempool-created output must stop being spendable after a child transaction spends it"
        );
        assert!(utxo_set.pool_unspent_outputs.contains_key(&child_outpoint));
        assert_eq!(utxo_set.get_outpoint_owner_id(&parent_outpoint), Some(&child.id()));
    }
}
