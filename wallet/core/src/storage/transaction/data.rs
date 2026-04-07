//!
//! Wallet transaction data variants.
//!

use super::UtxoRecord;
use crate::imports::*;
use cryptix_consensus_core::tx::Transaction;
pub use cryptix_consensus_core::tx::TransactionId;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
// the reason the struct is renamed kebab-case and then
// each field is renamed to camelCase is to force the
// enum tags to be lower-kebab-case.
#[serde(rename_all = "kebab-case")]
pub enum TransactionData {
    Reorg {
        #[serde(rename = "utxoEntries")]
        utxo_entries: Vec<UtxoRecord>,
        #[serde(rename = "value")]
        aggregate_input_value: u64,
        #[serde(rename = "transaction", skip_serializing_if = "Option::is_none")]
        #[serde(default)]
        transaction: Option<Transaction>,
    },
    Incoming {
        #[serde(rename = "utxoEntries")]
        utxo_entries: Vec<UtxoRecord>,
        #[serde(rename = "value")]
        aggregate_input_value: u64,
        #[serde(rename = "transaction", skip_serializing_if = "Option::is_none")]
        #[serde(default)]
        transaction: Option<Transaction>,
    },
    Stasis {
        #[serde(rename = "utxoEntries")]
        utxo_entries: Vec<UtxoRecord>,
        #[serde(rename = "value")]
        aggregate_input_value: u64,
        #[serde(rename = "transaction", skip_serializing_if = "Option::is_none")]
        #[serde(default)]
        transaction: Option<Transaction>,
    },
    External {
        #[serde(rename = "utxoEntries")]
        utxo_entries: Vec<UtxoRecord>,
        #[serde(rename = "value")]
        aggregate_input_value: u64,
        #[serde(rename = "transaction", skip_serializing_if = "Option::is_none")]
        #[serde(default)]
        transaction: Option<Transaction>,
    },
    Batch {
        fees: u64,
        #[serde(rename = "inputValue")]
        aggregate_input_value: u64,
        #[serde(rename = "outputValue")]
        aggregate_output_value: u64,
        transaction: Transaction,
        #[serde(rename = "paymentValue")]
        payment_value: Option<u64>,
        #[serde(rename = "changeValue")]
        change_value: u64,
        #[serde(rename = "acceptedDaaScore")]
        accepted_daa_score: Option<u64>,
        #[serde(rename = "utxoEntries")]
        #[serde(default)]
        utxo_entries: Vec<UtxoRecord>,
    },
    Outgoing {
        fees: u64,
        #[serde(rename = "inputValue")]
        aggregate_input_value: u64,
        #[serde(rename = "outputValue")]
        aggregate_output_value: u64,
        transaction: Transaction,
        #[serde(rename = "paymentValue")]
        payment_value: Option<u64>,
        #[serde(rename = "changeValue")]
        change_value: u64,
        #[serde(rename = "acceptedDaaScore")]
        accepted_daa_score: Option<u64>,
        #[serde(rename = "utxoEntries")]
        #[serde(default)]
        utxo_entries: Vec<UtxoRecord>,
    },
    TransferIncoming {
        fees: u64,
        #[serde(rename = "inputValue")]
        aggregate_input_value: u64,
        #[serde(rename = "outputValue")]
        aggregate_output_value: u64,
        transaction: Transaction,
        #[serde(rename = "paymentValue")]
        payment_value: Option<u64>,
        #[serde(rename = "changeValue")]
        change_value: u64,
        #[serde(rename = "acceptedDaaScore")]
        accepted_daa_score: Option<u64>,
        #[serde(rename = "utxoEntries")]
        utxo_entries: Vec<UtxoRecord>,
    },
    TransferOutgoing {
        fees: u64,
        #[serde(rename = "inputValue")]
        aggregate_input_value: u64,
        #[serde(rename = "outputValue")]
        aggregate_output_value: u64,
        transaction: Transaction,
        #[serde(rename = "paymentValue")]
        payment_value: Option<u64>,
        #[serde(rename = "changeValue")]
        change_value: u64,
        #[serde(rename = "acceptedDaaScore")]
        accepted_daa_score: Option<u64>,
        #[serde(rename = "utxoEntries")]
        utxo_entries: Vec<UtxoRecord>,
    },
    Change {
        #[serde(rename = "inputValue")]
        aggregate_input_value: u64,
        #[serde(rename = "outputValue")]
        aggregate_output_value: u64,
        transaction: Transaction,
        #[serde(rename = "paymentValue")]
        payment_value: Option<u64>,
        #[serde(rename = "changeValue")]
        change_value: u64,
        #[serde(rename = "acceptedDaaScore")]
        accepted_daa_score: Option<u64>,
        #[serde(rename = "utxoEntries")]
        utxo_entries: Vec<UtxoRecord>,
    },
}

impl TransactionData {
    const STORAGE_MAGIC: u32 = 0x54445854;
    const STORAGE_VERSION: u32 = 1;

    pub fn kind(&self) -> TransactionKind {
        match self {
            TransactionData::Reorg { .. } => TransactionKind::Reorg,
            TransactionData::Stasis { .. } => TransactionKind::Stasis,
            TransactionData::Incoming { .. } => TransactionKind::Incoming,
            TransactionData::External { .. } => TransactionKind::External,
            TransactionData::Outgoing { .. } => TransactionKind::Outgoing,
            TransactionData::Batch { .. } => TransactionKind::Batch,
            TransactionData::TransferIncoming { .. } => TransactionKind::TransferIncoming,
            TransactionData::TransferOutgoing { .. } => TransactionKind::TransferOutgoing,
            TransactionData::Change { .. } => TransactionKind::Change,
        }
    }

    pub fn has_address(&self, address: &Address) -> bool {
        match self {
            TransactionData::Reorg { utxo_entries, .. } => utxo_entries.iter().any(|utxo| utxo.address.as_ref() == Some(address)),
            TransactionData::Stasis { utxo_entries, .. } => utxo_entries.iter().any(|utxo| utxo.address.as_ref() == Some(address)),
            TransactionData::Incoming { utxo_entries, .. } => utxo_entries.iter().any(|utxo| utxo.address.as_ref() == Some(address)),
            TransactionData::External { utxo_entries, .. } => utxo_entries.iter().any(|utxo| utxo.address.as_ref() == Some(address)),
            TransactionData::Outgoing { utxo_entries, .. } => utxo_entries.iter().any(|utxo| utxo.address.as_ref() == Some(address)),
            TransactionData::Batch { utxo_entries, .. } => utxo_entries.iter().any(|utxo| utxo.address.as_ref() == Some(address)),
            TransactionData::TransferIncoming { utxo_entries, .. } => {
                utxo_entries.iter().any(|utxo| utxo.address.as_ref() == Some(address))
            }
            TransactionData::TransferOutgoing { utxo_entries, .. } => {
                utxo_entries.iter().any(|utxo| utxo.address.as_ref() == Some(address))
            }
            TransactionData::Change { utxo_entries, .. } => utxo_entries.iter().any(|utxo| utxo.address.as_ref() == Some(address)),
        }
    }

    pub fn transaction(&self) -> Option<&Transaction> {
        match self {
            TransactionData::Reorg { transaction, .. }
            | TransactionData::Incoming { transaction, .. }
            | TransactionData::Stasis { transaction, .. }
            | TransactionData::External { transaction, .. } => transaction.as_ref(),
            TransactionData::Batch { transaction, .. }
            | TransactionData::Outgoing { transaction, .. }
            | TransactionData::TransferIncoming { transaction, .. }
            | TransactionData::TransferOutgoing { transaction, .. }
            | TransactionData::Change { transaction, .. } => Some(transaction),
        }
    }

    pub fn attach_transaction_if_supported(&mut self, transaction: Transaction) -> bool {
        match self {
            TransactionData::Reorg { transaction: tx, .. }
            | TransactionData::Incoming { transaction: tx, .. }
            | TransactionData::Stasis { transaction: tx, .. }
            | TransactionData::External { transaction: tx, .. } => {
                *tx = Some(transaction);
                true
            }
            TransactionData::Batch { .. }
            | TransactionData::Outgoing { .. }
            | TransactionData::TransferIncoming { .. }
            | TransactionData::TransferOutgoing { .. }
            | TransactionData::Change { .. } => false,
        }
    }
}

impl BorshSerialize for TransactionData {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        StorageHeader::new(Self::STORAGE_MAGIC, Self::STORAGE_VERSION).serialize(writer)?;

        let kind = self.kind();
        BorshSerialize::serialize(&kind, writer)?;

        match self {
            TransactionData::Reorg { utxo_entries, aggregate_input_value, transaction } => {
                BorshSerialize::serialize(utxo_entries, writer)?;
                BorshSerialize::serialize(aggregate_input_value, writer)?;
                BorshSerialize::serialize(transaction, writer)?;
            }
            TransactionData::Incoming { utxo_entries, aggregate_input_value, transaction } => {
                BorshSerialize::serialize(utxo_entries, writer)?;
                BorshSerialize::serialize(aggregate_input_value, writer)?;
                BorshSerialize::serialize(transaction, writer)?;
            }
            TransactionData::Stasis { utxo_entries, aggregate_input_value, transaction } => {
                BorshSerialize::serialize(utxo_entries, writer)?;
                BorshSerialize::serialize(aggregate_input_value, writer)?;
                BorshSerialize::serialize(transaction, writer)?;
            }
            TransactionData::External { utxo_entries, aggregate_input_value, transaction } => {
                BorshSerialize::serialize(utxo_entries, writer)?;
                BorshSerialize::serialize(aggregate_input_value, writer)?;
                BorshSerialize::serialize(transaction, writer)?;
            }
            TransactionData::Batch {
                fees,
                aggregate_input_value,
                aggregate_output_value,
                transaction,
                payment_value,
                change_value,
                accepted_daa_score,
                utxo_entries,
            } => {
                BorshSerialize::serialize(fees, writer)?;
                BorshSerialize::serialize(aggregate_input_value, writer)?;
                BorshSerialize::serialize(aggregate_output_value, writer)?;
                BorshSerialize::serialize(transaction, writer)?;
                BorshSerialize::serialize(payment_value, writer)?;
                BorshSerialize::serialize(change_value, writer)?;
                BorshSerialize::serialize(accepted_daa_score, writer)?;
                BorshSerialize::serialize(utxo_entries, writer)?;
            }
            TransactionData::Outgoing {
                fees,
                aggregate_input_value,
                aggregate_output_value,
                transaction,
                payment_value,
                change_value,
                accepted_daa_score,
                utxo_entries,
            } => {
                BorshSerialize::serialize(fees, writer)?;
                BorshSerialize::serialize(aggregate_input_value, writer)?;
                BorshSerialize::serialize(aggregate_output_value, writer)?;
                BorshSerialize::serialize(transaction, writer)?;
                BorshSerialize::serialize(payment_value, writer)?;
                BorshSerialize::serialize(change_value, writer)?;
                BorshSerialize::serialize(accepted_daa_score, writer)?;
                BorshSerialize::serialize(utxo_entries, writer)?;
            }
            TransactionData::TransferIncoming {
                fees,
                aggregate_input_value,
                aggregate_output_value,
                transaction,
                payment_value,
                change_value,
                accepted_daa_score,
                utxo_entries,
            } => {
                BorshSerialize::serialize(fees, writer)?;
                BorshSerialize::serialize(aggregate_input_value, writer)?;
                BorshSerialize::serialize(aggregate_output_value, writer)?;
                BorshSerialize::serialize(transaction, writer)?;
                BorshSerialize::serialize(payment_value, writer)?;
                BorshSerialize::serialize(change_value, writer)?;
                BorshSerialize::serialize(accepted_daa_score, writer)?;
                BorshSerialize::serialize(utxo_entries, writer)?;
            }
            TransactionData::TransferOutgoing {
                fees,
                aggregate_input_value,
                aggregate_output_value,
                transaction,
                payment_value,
                change_value,
                accepted_daa_score,
                utxo_entries,
            } => {
                BorshSerialize::serialize(fees, writer)?;
                BorshSerialize::serialize(aggregate_input_value, writer)?;
                BorshSerialize::serialize(aggregate_output_value, writer)?;
                BorshSerialize::serialize(transaction, writer)?;
                BorshSerialize::serialize(payment_value, writer)?;
                BorshSerialize::serialize(change_value, writer)?;
                BorshSerialize::serialize(accepted_daa_score, writer)?;
                BorshSerialize::serialize(utxo_entries, writer)?;
            }
            TransactionData::Change {
                aggregate_input_value,
                aggregate_output_value,
                transaction,
                payment_value,
                change_value,
                accepted_daa_score,
                utxo_entries,
            } => {
                BorshSerialize::serialize(aggregate_input_value, writer)?;
                BorshSerialize::serialize(aggregate_output_value, writer)?;
                BorshSerialize::serialize(transaction, writer)?;
                BorshSerialize::serialize(payment_value, writer)?;
                BorshSerialize::serialize(change_value, writer)?;
                BorshSerialize::serialize(accepted_daa_score, writer)?;
                BorshSerialize::serialize(utxo_entries, writer)?;
            }
        }

        Ok(())
    }
}

impl BorshDeserialize for TransactionData {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> IoResult<Self> {
        let StorageHeader { version, .. } =
            StorageHeader::deserialize_reader(reader)?.try_magic(Self::STORAGE_MAGIC)?.try_version(Self::STORAGE_VERSION)?;

        let kind: TransactionKind = BorshDeserialize::deserialize_reader(reader)?;

        match kind {
            TransactionKind::Reorg => {
                let utxo_entries: Vec<UtxoRecord> = BorshDeserialize::deserialize_reader(reader)?;
                let aggregate_input_value: u64 = BorshDeserialize::deserialize_reader(reader)?;
                let transaction = if version >= 1 { BorshDeserialize::deserialize_reader(reader)? } else { None };
                Ok(TransactionData::Reorg { utxo_entries, aggregate_input_value, transaction })
            }
            TransactionKind::Incoming => {
                let utxo_entries: Vec<UtxoRecord> = BorshDeserialize::deserialize_reader(reader)?;
                let aggregate_input_value: u64 = BorshDeserialize::deserialize_reader(reader)?;
                let transaction = if version >= 1 { BorshDeserialize::deserialize_reader(reader)? } else { None };
                Ok(TransactionData::Incoming { utxo_entries, aggregate_input_value, transaction })
            }
            TransactionKind::Stasis => {
                let utxo_entries: Vec<UtxoRecord> = BorshDeserialize::deserialize_reader(reader)?;
                let aggregate_input_value: u64 = BorshDeserialize::deserialize_reader(reader)?;
                let transaction = if version >= 1 { BorshDeserialize::deserialize_reader(reader)? } else { None };
                Ok(TransactionData::Stasis { utxo_entries, aggregate_input_value, transaction })
            }
            TransactionKind::External => {
                let utxo_entries: Vec<UtxoRecord> = BorshDeserialize::deserialize_reader(reader)?;
                let aggregate_input_value: u64 = BorshDeserialize::deserialize_reader(reader)?;
                let transaction = if version >= 1 { BorshDeserialize::deserialize_reader(reader)? } else { None };
                Ok(TransactionData::External { utxo_entries, aggregate_input_value, transaction })
            }
            TransactionKind::Batch => {
                let fees: u64 = BorshDeserialize::deserialize_reader(reader)?;
                let aggregate_input_value: u64 = BorshDeserialize::deserialize_reader(reader)?;
                let aggregate_output_value: u64 = BorshDeserialize::deserialize_reader(reader)?;
                let transaction: Transaction = BorshDeserialize::deserialize_reader(reader)?;
                let payment_value: Option<u64> = BorshDeserialize::deserialize_reader(reader)?;
                let change_value: u64 = BorshDeserialize::deserialize_reader(reader)?;
                let accepted_daa_score: Option<u64> = BorshDeserialize::deserialize_reader(reader)?;
                let utxo_entries: Vec<UtxoRecord> = BorshDeserialize::deserialize_reader(reader)?;
                Ok(TransactionData::Batch {
                    fees,
                    aggregate_input_value,
                    aggregate_output_value,
                    transaction,
                    payment_value,
                    change_value,
                    accepted_daa_score,
                    utxo_entries,
                })
            }
            TransactionKind::Outgoing => {
                let fees: u64 = BorshDeserialize::deserialize_reader(reader)?;
                let aggregate_input_value: u64 = BorshDeserialize::deserialize_reader(reader)?;
                let aggregate_output_value: u64 = BorshDeserialize::deserialize_reader(reader)?;
                let transaction: Transaction = BorshDeserialize::deserialize_reader(reader)?;
                let payment_value: Option<u64> = BorshDeserialize::deserialize_reader(reader)?;
                let change_value: u64 = BorshDeserialize::deserialize_reader(reader)?;
                let accepted_daa_score: Option<u64> = BorshDeserialize::deserialize_reader(reader)?;
                let utxo_entries: Vec<UtxoRecord> = BorshDeserialize::deserialize_reader(reader)?;
                Ok(TransactionData::Outgoing {
                    fees,
                    aggregate_input_value,
                    aggregate_output_value,
                    transaction,
                    payment_value,
                    change_value,
                    accepted_daa_score,
                    utxo_entries,
                })
            }
            TransactionKind::TransferIncoming => {
                let fees: u64 = BorshDeserialize::deserialize_reader(reader)?;
                let aggregate_input_value: u64 = BorshDeserialize::deserialize_reader(reader)?;
                let aggregate_output_value: u64 = BorshDeserialize::deserialize_reader(reader)?;
                let transaction: Transaction = BorshDeserialize::deserialize_reader(reader)?;
                let payment_value: Option<u64> = BorshDeserialize::deserialize_reader(reader)?;
                let change_value: u64 = BorshDeserialize::deserialize_reader(reader)?;
                let accepted_daa_score: Option<u64> = BorshDeserialize::deserialize_reader(reader)?;
                let utxo_entries: Vec<UtxoRecord> = BorshDeserialize::deserialize_reader(reader)?;
                Ok(TransactionData::TransferIncoming {
                    fees,
                    aggregate_input_value,
                    aggregate_output_value,
                    transaction,
                    payment_value,
                    change_value,
                    accepted_daa_score,
                    utxo_entries,
                })
            }
            TransactionKind::TransferOutgoing => {
                let fees: u64 = BorshDeserialize::deserialize_reader(reader)?;
                let aggregate_input_value: u64 = BorshDeserialize::deserialize_reader(reader)?;
                let aggregate_output_value: u64 = BorshDeserialize::deserialize_reader(reader)?;
                let transaction: Transaction = BorshDeserialize::deserialize_reader(reader)?;
                let payment_value: Option<u64> = BorshDeserialize::deserialize_reader(reader)?;
                let change_value: u64 = BorshDeserialize::deserialize_reader(reader)?;
                let accepted_daa_score: Option<u64> = BorshDeserialize::deserialize_reader(reader)?;
                let utxo_entries: Vec<UtxoRecord> = BorshDeserialize::deserialize_reader(reader)?;
                Ok(TransactionData::TransferOutgoing {
                    fees,
                    aggregate_input_value,
                    aggregate_output_value,
                    transaction,
                    payment_value,
                    change_value,
                    accepted_daa_score,
                    utxo_entries,
                })
            }
            TransactionKind::Change => {
                let aggregate_input_value: u64 = BorshDeserialize::deserialize_reader(reader)?;
                let aggregate_output_value: u64 = BorshDeserialize::deserialize_reader(reader)?;
                let transaction: Transaction = BorshDeserialize::deserialize_reader(reader)?;
                let payment_value: Option<u64> = BorshDeserialize::deserialize_reader(reader)?;
                let change_value: u64 = BorshDeserialize::deserialize_reader(reader)?;
                let accepted_daa_score: Option<u64> = BorshDeserialize::deserialize_reader(reader)?;
                let utxo_entries: Vec<UtxoRecord> = BorshDeserialize::deserialize_reader(reader)?;
                Ok(TransactionData::Change {
                    aggregate_input_value,
                    aggregate_output_value,
                    transaction,
                    payment_value,
                    change_value,
                    accepted_daa_score,
                    utxo_entries,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptix_consensus_core::subnets::SUBNETWORK_ID_NATIVE;

    #[test]
    fn deserialize_v0_incoming_without_transaction() {
        let mut bytes = Vec::new();
        BorshSerialize::serialize(&StorageHeader::new(TransactionData::STORAGE_MAGIC, 0), &mut bytes).unwrap();
        BorshSerialize::serialize(&TransactionKind::Incoming, &mut bytes).unwrap();
        let utxo_entries: Vec<UtxoRecord> = vec![];
        BorshSerialize::serialize(&utxo_entries, &mut bytes).unwrap();
        BorshSerialize::serialize(&42u64, &mut bytes).unwrap();

        let decoded = TransactionData::deserialize_reader(&mut bytes.as_slice()).unwrap();
        match decoded {
            TransactionData::Incoming { aggregate_input_value, transaction, .. } => {
                assert_eq!(aggregate_input_value, 42);
                assert!(transaction.is_none());
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn attach_transaction_to_incoming_record() {
        let mut data = TransactionData::Incoming { utxo_entries: vec![], aggregate_input_value: 0, transaction: None };
        let tx = Transaction::new(0, vec![], vec![], 0, SUBNETWORK_ID_NATIVE, 0, vec![1, 2, 3]);
        assert!(data.attach_transaction_if_supported(tx.clone()));
        assert_eq!(data.transaction().unwrap().payload, tx.payload);
    }
}
