use crate::RpcUtxoEntry;
use crate::RpcUtxosByAddressesEntry;
use cryptix_addresses::Prefix;
use cryptix_index_core::indexed_utxos::UtxoSetByScriptPublicKey;
use cryptix_txscript::extract_script_pub_key_address;

// ----------------------------------------------------------------------------
// index to rpc_core
// ----------------------------------------------------------------------------

pub fn utxo_set_into_rpc(item: &UtxoSetByScriptPublicKey, prefix: Option<Prefix>) -> Vec<RpcUtxosByAddressesEntry> {
    item.iter()
        .flat_map(|(script_public_key, utxo_collection)| {
            let address = prefix.and_then(|x| extract_script_pub_key_address(script_public_key, x).ok());
            utxo_collection
                .iter()
                .map(|(outpoint, entry)| RpcUtxosByAddressesEntry {
                    address: address.clone(),
                    outpoint: (*outpoint).into(),
                    utxo_entry: RpcUtxoEntry::new(entry.amount, script_public_key.clone(), entry.block_daa_score, entry.is_coinbase),
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>()
}
