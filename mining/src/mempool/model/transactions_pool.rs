use crate::{
    feerate::{FeerateEstimator, FeerateEstimatorArgs},
    mempool::{
        config::Config,
        errors::{RuleError, RuleResult},
        model::{
            map::MempoolTransactionCollection,
            pool::{Pool, TransactionsEdges},
            tx::{DoubleSpend, MempoolTransaction},
            utxo_set::MempoolUtxoSet,
        },
        tx::Priority,
    },
    model::{topological_index::TopologicalIndex, TransactionIdSet},
    Policy,
};
use cryptix_consensus_core::{
    block::TemplateTransactionSelector,
    tx::{MutableTransaction, TransactionId, TransactionOutpoint},
};
use cryptix_core::{debug, time::unix_now, trace};
use std::{
    collections::{hash_map::Keys, hash_set::Iter, HashMap},
    iter::once,
    sync::Arc,
};

use super::frontier::Frontier;

/// Pool of transactions to be included in a block template
///
/// ### Rust rewrite notes
///
/// The main design decision is to have [MempoolTransaction]s owned by [all_transactions]
/// without any other external reference so no smart pointer is needed.
///
/// This has following consequences:
///
/// - highPriorityTransactions is dropped in favour of an in-place filtered iterator.
/// - MempoolTransaction.parentTransactionsInPool is moved here and replaced by a map from
///   an id to a set of parent transaction ids introducing an indirection stage when
///   a matching object is required.
/// - chainedTransactionsByParentID maps an id instead of a transaction reference
///   introducing a indirection stage when the matching object is required.
/// - Hash sets are used by parent_transaction_ids_in_pool and chained_transaction_ids_by_parent_id
///   instead of vectors to prevent duplicates.
/// - transactionsOrderedByFeeRate is dropped and replaced by an in-place vector
///   of low-priority transactions sorted by fee rates. This design might eventually
///   prove to be sub-optimal, in which case an index should be implemented, probably
///   requiring smart pointers eventually or an indirection stage too.
pub(crate) struct TransactionsPool {
    /// Mempool config
    config: Arc<Config>,

    /// Store of transactions.
    /// Any mutable access to this map should be carefully reviewed for consistency with all other collections
    /// and fields of this struct. In particular, `estimated_size` must reflect the exact sum of estimated size
    /// for all current transactions in this collection.
    all_transactions: MempoolTransactionCollection,

    /// Transactions dependencies formed by inputs present in pool - ancestor relations.
    parent_transactions: TransactionsEdges,

    /// Transactions dependencies formed by outputs present in pool - successor relations.
    chained_transactions: TransactionsEdges,

    /// Transactions with no parents in the mempool -- ready to be inserted into a block template
    ready_transactions: Frontier,

    last_expire_scan_daa_score: u64,

    /// last expire scan time in milliseconds
    last_expire_scan_time: u64,

    /// Sum of estimated size for all transactions currently held in `all_transactions`
    estimated_size: usize,

    /// Store of UTXOs
    utxo_set: MempoolUtxoSet,

    /// Tracks the number of payload transactions per script public key (wallet)
    payload_transaction_count_per_wallet: HashMap<Vec<u8>, usize>,
}

impl TransactionsPool {
    pub(crate) fn new(config: Arc<Config>) -> Self {
        Self {
            config,
            all_transactions: MempoolTransactionCollection::default(),
            parent_transactions: TransactionsEdges::default(),
            chained_transactions: TransactionsEdges::default(),
            ready_transactions: Default::default(),
            last_expire_scan_daa_score: 0,
            last_expire_scan_time: unix_now(),
            utxo_set: MempoolUtxoSet::new(),
            estimated_size: 0,
            payload_transaction_count_per_wallet: HashMap::new(),
        }
    }

    /// Add a mutable transaction to the pool
    pub(crate) fn add_transaction(
        &mut self,
        transaction: MutableTransaction,
        virtual_daa_score: u64,
        priority: Priority,
        transaction_size: usize,
    ) -> RuleResult<&MempoolTransaction> {
        let transaction = MempoolTransaction::new(transaction, priority, virtual_daa_score);
        let id = transaction.id();
        self.add_mempool_transaction(transaction, transaction_size)?;
        Ok(self.get(&id).unwrap())
    }

    fn collect_input_wallet_scripts(&self, mtx: &MutableTransaction) -> std::collections::HashSet<Vec<u8>> {
        let mut scripts = std::collections::HashSet::new();

        for (i, input) in mtx.tx.inputs.iter().enumerate() {
            if let Some(utxo_entry) = &mtx.entries[i] {
                scripts.insert(utxo_entry.script_public_key.script().to_vec());
            } else if let Some(utxo_entry) = self.utxo_set.pool_unspent_outputs.get(&input.previous_outpoint) {
                scripts.insert(utxo_entry.script_public_key.script().to_vec());
            }
        }

        scripts
    }

    /// Add a mempool transaction to the pool
    pub(crate) fn add_mempool_transaction(&mut self, transaction: MempoolTransaction, transaction_size: usize) -> RuleResult<()> {
        let id = transaction.id();

        assert!(!self.all_transactions.contains_key(&id), "transaction {id} to be added already exists in the transactions pool");
        assert!(transaction.mtx.is_fully_populated(), "transaction {id} to be added in the transactions pool is not fully populated");

        let mut wallet_scripts = std::collections::HashSet::new();
        if !transaction.mtx.tx.is_coinbase() && !transaction.mtx.tx.payload.is_empty() {
            wallet_scripts = self.collect_input_wallet_scripts(&transaction.mtx);

            for script in &wallet_scripts {
                let count = self.payload_transaction_count_per_wallet.get(script).copied().unwrap_or(0);
                if count >= self.config.maximum_payload_transactions_per_wallet {
                    return Err(RuleError::RejectWalletPayloadTransactionLimitExceeded(format!("{:x?}", script), count));
                }
            }
        }

        let parents = self.get_parent_transaction_ids_in_pool(&transaction.mtx);
        self.parent_transactions.insert(id, parents.clone());
        if parents.is_empty() {
            self.ready_transactions.insert((&transaction).into());
        }
        for parent_id in parents {
            let entry = self.chained_transactions.entry(parent_id).or_default();
            entry.insert(id);
        }

        self.utxo_set.add_transaction(&transaction.mtx);
        self.estimated_size += transaction_size;

        if !wallet_scripts.is_empty() {
            for script in wallet_scripts {
                *self.payload_transaction_count_per_wallet.entry(script).or_insert(0) += 1;
            }
        }

        self.all_transactions.insert(id, transaction);
        trace!("Added transaction {}", id);
        Ok(())
    }

    pub(crate) fn remove_transaction(&mut self, transaction_id: &TransactionId) -> RuleResult<MempoolTransaction> {
        if let Some(removed_tx) = self.all_transactions.get(transaction_id) {
            if !removed_tx.mtx.tx.is_coinbase() && !removed_tx.mtx.tx.payload.is_empty() {
                let wallet_scripts = self.collect_input_wallet_scripts(&removed_tx.mtx);
                for script in wallet_scripts {
                    if let Some(count) = self.payload_transaction_count_per_wallet.get_mut(&script) {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            self.payload_transaction_count_per_wallet.remove(&script);
                        }
                    }
                }
            }
        }

        if let Some(parents) = self.parent_transactions.get(transaction_id) {
            for parent in parents.iter() {
                if let Some(chains) = self.chained_transactions.get_mut(parent) {
                    chains.remove(transaction_id);
                }
            }
        }
        if let Some(chains) = self.chained_transactions.get(transaction_id) {
            for chain in chains.iter() {
                if let Some(parents) = self.parent_transactions.get_mut(chain) {
                    parents.remove(transaction_id);
                    if parents.is_empty() {
                        let tx = self.all_transactions.get(chain).unwrap();
                        self.ready_transactions.insert(tx.into());
                    }
                }
            }
        }
        self.parent_transactions.remove(transaction_id);
        self.chained_transactions.remove(transaction_id);

        // Remove the transaction itself
        let removed_tx = self.all_transactions.remove(transaction_id).ok_or(RuleError::RejectMissingTransaction(*transaction_id))?;

        self.ready_transactions.remove(&(&removed_tx).into());

        // TODO: consider using `self.parent_transactions.get(transaction_id)`
        // The tradeoff to consider is whether it might be possible that a parent tx exists in the pool
        // however its relation as parent is not registered. This can supposedly happen in rare cases where
        // the parent was removed w/o redeemers and then re-added
        let parent_ids = self.get_parent_transaction_ids_in_pool(&removed_tx.mtx);

        // Remove the transaction from the mempool UTXO set
        self.utxo_set.remove_transaction(&removed_tx.mtx, &parent_ids);
        self.estimated_size -= removed_tx.mtx.mempool_estimated_bytes();

        if self.all_transactions.is_empty() {
            assert_eq!(0, self.estimated_size, "Sanity test -- if tx pool is empty, estimated byte size should be zero");
        }

        Ok(removed_tx)
    }

    pub(crate) fn update_revalidated_transaction(&mut self, transaction: MutableTransaction) -> bool {
        if let Some(tx) = self.all_transactions.get_mut(&transaction.id()) {
            // Make sure to update the overall estimated size since the updated transaction might have a different size
            self.estimated_size -= tx.mtx.mempool_estimated_bytes();
            tx.mtx = transaction;
            self.estimated_size += tx.mtx.mempool_estimated_bytes();
            true
        } else {
            false
        }
    }

    pub(crate) fn ready_transaction_count(&self) -> usize {
        self.ready_transactions.len()
    }

    pub(crate) fn ready_transaction_total_mass(&self) -> u64 {
        self.ready_transactions.total_mass()
    }

    /// Dynamically builds a transaction selector based on the specific state of the ready transactions frontier
    pub(crate) fn build_selector(&self) -> Box<dyn TemplateTransactionSelector> {
        self.ready_transactions.build_selector(&Policy::new(self.config.maximum_mass_per_block))
    }

    /// Builds a feerate estimator based on internal state of the ready transactions frontier
    pub(crate) fn build_feerate_estimator(&self, args: FeerateEstimatorArgs) -> FeerateEstimator {
        self.ready_transactions.build_feerate_estimator(args)
    }

    /// Returns the exceeding low-priority transactions having the lowest fee rates in order
    /// to make room for `transaction`. The returned transactions
    /// are guaranteed to be unchained (no successor in mempool) and to not be parent of
    /// `transaction`.
    ///
    /// An error is returned if the mempool is filled with high priority transactions, or
    /// there are not enough lower feerate transactions that can be removed to accommodate `transaction`
    pub(crate) fn limit_transaction_count(
        &self,
        transaction: &MutableTransaction,
        transaction_size: usize,
    ) -> RuleResult<Vec<TransactionId>> {
        // No eviction needed -- return
        if self.len() < self.config.maximum_transaction_count
            && self.estimated_size + transaction_size <= self.config.mempool_size_limit
        {
            return Ok(Default::default());
        }

        // Returns a vector of transactions to be removed (the caller has to actually remove)
        let feerate_threshold = transaction.calculated_feerate().unwrap();
        let mut txs_to_remove = Vec::with_capacity(1); // Normally we expect a single removal
        let mut selection_overall_size = 0;
        for tx in self
            .ready_transactions
            .ascending_iter()
            .map(|tx| self.all_transactions.get(&tx.id()).unwrap())
            .filter(|mtx| mtx.priority == Priority::Low)
        {
            // TODO (optimization): inline the `has_parent_in_set` check within the redeemer traversal and exit early if possible
            let redeemers = self.get_redeemer_ids_in_pool(&tx.id()).into_iter().chain(once(tx.id())).collect::<TransactionIdSet>();
            if transaction.has_parent_in_set(&redeemers) {
                continue;
            }

            // We are iterating ready txs by ascending feerate so the pending tx has lower feerate than all remaining txs
            if tx.fee_rate() > feerate_threshold {
                let err = RuleError::RejectMempoolIsFull;
                debug!("Transaction {} with feerate {} has been rejected: {}", transaction.id(), feerate_threshold, err);
                return Err(err);
            }

            txs_to_remove.push(tx.id());
            selection_overall_size += tx.mtx.mempool_estimated_bytes();

            if self.len() + 1 - txs_to_remove.len() <= self.config.maximum_transaction_count
                && self.estimated_size + transaction_size - selection_overall_size <= self.config.mempool_size_limit
            {
                return Ok(txs_to_remove);
            }
        }

        // We could not find sufficient space for the pending transaction
        debug!(
            "Mempool is filled with high-priority/ancestor txs (count: {}, bytes: {}). Transaction {} with feerate {} and size {} has been rejected: {}",
            self.len(),
            self.estimated_size,
            transaction.id(),
            feerate_threshold,
            transaction_size,
            RuleError::RejectMempoolIsFull
        );
        Err(RuleError::RejectMempoolIsFull)
    }

    pub(crate) fn get_estimated_size(&self) -> usize {
        self.estimated_size
    }

    pub(crate) fn all_transaction_ids_with_priority(&self, priority: Priority) -> Vec<TransactionId> {
        self.all().values().filter_map(|x| if x.priority == priority { Some(x.id()) } else { None }).collect()
    }

    pub(crate) fn get_outpoint_owner_id(&self, outpoint: &TransactionOutpoint) -> Option<&TransactionId> {
        self.utxo_set.get_outpoint_owner_id(outpoint)
    }

    /// Make sure no other transaction in the mempool is already spending an output which one of this transaction inputs spends
    pub(crate) fn check_double_spends(&self, transaction: &MutableTransaction) -> RuleResult<()> {
        self.utxo_set.check_double_spends(transaction)
    }

    /// Returns the first double spend of every transaction in the mempool double spending on `transaction`
    pub(crate) fn get_double_spend_transaction_ids(&self, transaction: &MutableTransaction) -> Vec<DoubleSpend> {
        self.utxo_set.get_double_spend_transaction_ids(transaction)
    }

    pub(crate) fn get_double_spend_owner<'a>(&'a self, double_spend: &DoubleSpend) -> RuleResult<&'a MempoolTransaction> {
        match self.get(&double_spend.owner_id) {
            Some(transaction) => Ok(transaction),
            None => {
                // This case should never arise in the first place.
                // Anyway, in case it does, if a double spent transaction id is found but the matching
                // transaction cannot be located in the mempool a replacement is no longer possible
                // so a double spend error is returned.
                Err(double_spend.into())
            }
        }
    }

    pub(crate) fn collect_expired_low_priority_transactions(&mut self, virtual_daa_score: u64) -> Vec<TransactionId> {
        let now = unix_now();
        if virtual_daa_score < self.last_expire_scan_daa_score + self.config.transaction_expire_scan_interval_daa_score
            || now < self.last_expire_scan_time + self.config.transaction_expire_scan_interval_milliseconds
        {
            return vec![];
        }

        self.last_expire_scan_daa_score = virtual_daa_score;
        self.last_expire_scan_time = now;

        // Never expire high priority transactions
        // Remove all transactions whose added_at_daa_score is older then transaction_expire_interval_daa_score
        self.all_transactions
            .values()
            .filter_map(|x| {
                if (x.priority == Priority::Low)
                    && virtual_daa_score > x.added_at_daa_score + self.config.transaction_expire_interval_daa_score
                {
                    Some(x.id())
                } else {
                    None
                }
            })
            .collect()
    }
}

type IterTxId<'a> = Iter<'a, TransactionId>;
type KeysTxId<'a> = Keys<'a, TransactionId, MempoolTransaction>;

impl<'a> TopologicalIndex<'a, KeysTxId<'a>, IterTxId<'a>, TransactionId> for TransactionsPool {
    fn topology_nodes(&'a self) -> KeysTxId<'a> {
        self.all_transactions.keys()
    }

    fn topology_node_edges(&'a self, key: &TransactionId) -> Option<IterTxId<'a>> {
        self.chained_transactions.get(key).map(|x| x.iter())
    }
}

impl Pool for TransactionsPool {
    #[inline]
    fn all(&self) -> &MempoolTransactionCollection {
        &self.all_transactions
    }

    #[inline]
    fn chained(&self) -> &TransactionsEdges {
        &self.chained_transactions
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use cryptix_consensus_core::{
        constants::TX_VERSION,
        subnets::SUBNETWORK_ID_NATIVE,
        tx::{
            ScriptPublicKey, Transaction, TransactionInput, TransactionOutput, TransactionOutpoint,
            UtxoEntry,
        },
    };
    use cryptix_core::time::unix_now;
    use std::sync::Arc;

    fn create_test_config() -> Arc<Config> {
        Arc::new(Config {
            maximum_transaction_count: 1000,
            mempool_size_limit: 1_000_000,
            maximum_build_block_template_attempts: 5,
            transaction_expire_interval_daa_score: 24 * 60 * 60 * 1000,
            transaction_expire_scan_interval_daa_score: 60 * 1000,
            transaction_expire_scan_interval_milliseconds: 60 * 1000,
            accepted_transaction_expire_interval_daa_score: 120 * 1000,
            accepted_transaction_expire_scan_interval_daa_score: 10 * 1000,
            accepted_transaction_expire_scan_interval_milliseconds: 10 * 1000,
            orphan_expire_interval_daa_score: 60 * 1000,
            orphan_expire_scan_interval_daa_score: 10 * 1000,
            maximum_orphan_transaction_mass: 100_000,
            maximum_orphan_transaction_count: 500,
            accept_non_standard: false,
            maximum_mass_per_block: 500_000,
            minimum_relay_transaction_fee: 1000,
            minimum_standard_transaction_version: TX_VERSION,
            maximum_standard_transaction_version: TX_VERSION,
            maximum_payload_transactions_per_wallet: 25,
            network_blocks_per_second: 1,
        })
    }

    fn create_test_script() -> ScriptPublicKey {
        use smallvec::SmallVec;
        let script: SmallVec<[u8; 36]> = vec![
            0x76, 0xa9, 0x14,
            0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00,
            0x88, 0xac,
        ]
        .into();
        ScriptPublicKey::new(0, script)
    }

    fn create_payload_transaction(script: &ScriptPublicKey, payload: Vec<u8>) -> MutableTransaction {
        let tx = Transaction::new(
            TX_VERSION,
            vec![TransactionInput {
                previous_outpoint: TransactionOutpoint::new(
                    TransactionId::from_slice(&[0; 32]),
                    0,
                ),
                signature_script: vec![],
                sequence: u64::MAX,
                sig_op_count: 0,
            }],
            vec![TransactionOutput {
                value: 1000,
                script_public_key: script.clone(),
                payload: vec![],
            }],
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            payload,
        );

        let mut mtx = MutableTransaction::from_tx(tx);

        mtx.entries = vec![Some(UtxoEntry::new(
            2000,
            script.clone(),
            0,
            false,
        ))];

        mtx.calculated_compute_mass = Some(1000);
        mtx.calculated_fee = Some(1000);
        mtx.tx.set_mass(1000);

        mtx
    }

    #[test]
    fn test_wallet_payload_limit() {
        let config = create_test_config();
        let mut pool = TransactionsPool::new(config.clone());
        let script = create_test_script();

        for i in 0..25 {
            let tx = create_payload_transaction(&script, vec![i as u8]);
            let mempool_tx = MempoolTransaction::new(tx, Priority::Low, unix_now());
            assert!(pool.add_mempool_transaction(mempool_tx, 1000).is_ok());
        }

        assert_eq!(
            pool.payload_transaction_count_per_wallet.get(&script.script().to_vec()),
            Some(&25)
        );

        let tx = create_payload_transaction(&script, vec![25]);
        let mempool_tx = MempoolTransaction::new(tx, Priority::Low, unix_now());
        assert!(matches!(
            pool.add_mempool_transaction(mempool_tx, 1000),
            Err(RuleError::RejectWalletPayloadTransactionLimitExceeded(_, 25))
        ));

        let tx_id = pool.all_transactions.keys().next().unwrap().clone();
        assert!(pool.remove_transaction(&tx_id).is_ok());
        assert_eq!(
            pool.payload_transaction_count_per_wallet.get(&script.script().to_vec()),
            Some(&24)
        );

        let tx = create_payload_transaction(&script, vec![26]);
        let mempool_tx = MempoolTransaction::new(tx, Priority::Low, unix_now());
        assert!(pool.add_mempool_transaction(mempool_tx, 1000).is_ok());
        assert_eq!(
            pool.payload_transaction_count_per_wallet.get(&script.script().to_vec()),
            Some(&25)
        );
    }

    #[test]
    fn test_non_payload_transactions_not_counted() {
        let config = create_test_config();
        let mut pool = TransactionsPool::new(config.clone());
        let script = create_test_script();

        for _ in 0..50 {
            let tx = create_payload_transaction(&script, vec![]);
            let mempool_tx = MempoolTransaction::new(tx, Priority::Low, unix_now());
            assert!(pool.add_mempool_transaction(mempool_tx, 1000).is_ok());
        }

        assert_eq!(
            pool.payload_transaction_count_per_wallet.get(&script.script().to_vec()),
            None
        );
    }

    #[test]
    fn test_coinbase_transactions_not_counted() {
        let config = create_test_config();
        let mut pool = TransactionsPool::new(config.clone());
        let script = create_test_script();

        let tx = Transaction::new(
            TX_VERSION,
            vec![], 
            vec![TransactionOutput {
                value: 1000,
                script_public_key: script.clone(),
                payload: vec![],
            }],
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            vec![1, 2, 3],
        );

        let mut mtx = MutableTransaction::from_tx(tx);

        mtx.entries = vec![];

        mtx.calculated_compute_mass = Some(1000); 
        mtx.calculated_fee = Some(0); 
        mtx.tx.set_mass(1000); 

        let mempool_tx = MempoolTransaction::new(mtx, Priority::Low, unix_now());
        assert!(pool.add_mempool_transaction(mempool_tx, 1000).is_ok());

        assert_eq!(
            pool.payload_transaction_count_per_wallet.get(&script.script().to_vec()),
            None
        );
    }
}
