use super::{
    error::ConversionError,
    model::{
        trusted::{TrustedDataEntry, TrustedDataPackage},
        version::Version,
    },
    option::TryIntoOptionEx,
};
use crate::pb as protowire;
use cryptix_consensus_core::{
    header::Header,
    pruning::{PruningPointProof, PruningPointsList},
    tx::{TransactionId, TransactionOutpoint, UtxoEntry},
};
use cryptix_hashes::Hash;
use cryptix_utils::networking::{IpAddress, PeerId};

use std::sync::Arc;

const PQ_MLKEM1024_PUBLIC_KEY_SIZE: usize = 1568;

// ----------------------------------------------------------------------------
// consensus_core to protowire
// ----------------------------------------------------------------------------

impl From<Version> for protowire::VersionMessage {
    fn from(item: Version) -> Self {
        Self {
            protocol_version: item.protocol_version,
            services: item.services,
            timestamp: item.timestamp as i64,
            address: item.address.map(|x| x.into()),
            id: item.id.as_bytes().to_vec(),
            user_agent: item.user_agent,
            disable_relay_tx: item.disable_relay_tx,
            subnetwork_id: item.subnetwork_id.map(|x| x.into()),
            network: item.network.clone(),
            anti_fraud_hashes: item.anti_fraud_hashes.into_iter().map(|v| v.to_vec()).collect(),
            node_pubkey_xonly: item.node_pubkey_xonly.map(|value| value.to_vec()).unwrap_or_default(),
            node_pow_nonce: item.node_pow_nonce,
            node_challenge_nonce: item.node_challenge_nonce,
            pq_ml_kem1024_pubkey: item.pq_ml_kem1024_pubkey.unwrap_or_default(),
        }
    }
}

// ----------------------------------------------------------------------------
// protowire to consensus_core
// ----------------------------------------------------------------------------

impl TryFrom<protowire::VersionMessage> for Version {
    type Error = ConversionError;
    fn try_from(msg: protowire::VersionMessage) -> Result<Self, Self::Error> {
        Ok(Self {
            protocol_version: msg.protocol_version,
            services: msg.services,
            timestamp: msg.timestamp as u64,
            address: if msg.address.is_none() { None } else { Some(msg.address.unwrap().try_into()?) },
            id: PeerId::from_slice(&msg.id)?,
            user_agent: msg.user_agent.clone(),
            disable_relay_tx: msg.disable_relay_tx,
            subnetwork_id: if msg.subnetwork_id.is_none() { None } else { Some(msg.subnetwork_id.unwrap().try_into()?) },
            network: msg.network.clone(),
            anti_fraud_hashes: parse_anti_fraud_hashes(msg.anti_fraud_hashes)?,
            node_pubkey_xonly: parse_optional_32_bytes(msg.node_pubkey_xonly)?,
            node_pow_nonce: msg.node_pow_nonce,
            node_challenge_nonce: msg.node_challenge_nonce,
            pq_ml_kem1024_pubkey: parse_optional_mlkem1024_pubkey(msg.pq_ml_kem1024_pubkey)?,
        })
    }
}

fn parse_anti_fraud_hashes(raw: Vec<Vec<u8>>) -> Result<Vec<[u8; 32]>, ConversionError> {
    if raw.len() > 3 {
        return Err(ConversionError::General);
    }
    raw.into_iter().map(|entry| entry.as_slice().try_into().map_err(|_| ConversionError::General)).collect()
}

fn parse_optional_32_bytes(raw: Vec<u8>) -> Result<Option<[u8; 32]>, ConversionError> {
    if raw.is_empty() {
        return Ok(None);
    }
    let value: [u8; 32] = raw.as_slice().try_into().map_err(|_| ConversionError::General)?;
    Ok(Some(value))
}

fn parse_optional_mlkem1024_pubkey(raw: Vec<u8>) -> Result<Option<Vec<u8>>, ConversionError> {
    if raw.is_empty() {
        return Ok(None);
    }
    if raw.len() != PQ_MLKEM1024_PUBLIC_KEY_SIZE {
        return Err(ConversionError::General);
    }
    Ok(Some(raw))
}

impl TryFrom<protowire::RequestHeadersMessage> for (Hash, Hash) {
    type Error = ConversionError;
    fn try_from(msg: protowire::RequestHeadersMessage) -> Result<Self, Self::Error> {
        Ok((msg.high_hash.try_into_ex()?, msg.low_hash.try_into_ex()?))
    }
}

impl TryFrom<protowire::RequestIbdChainBlockLocatorMessage> for (Option<Hash>, Option<Hash>) {
    type Error = ConversionError;
    fn try_from(msg: protowire::RequestIbdChainBlockLocatorMessage) -> Result<Self, Self::Error> {
        let low = match msg.low_hash {
            Some(low) => Some(low.try_into()?),
            None => None,
        };

        let high = match msg.high_hash {
            Some(high) => Some(high.try_into()?),
            None => None,
        };

        Ok((low, high))
    }
}

impl TryFrom<protowire::PruningPointProofMessage> for PruningPointProof {
    type Error = ConversionError;
    fn try_from(msg: protowire::PruningPointProofMessage) -> Result<Self, Self::Error> {
        msg.headers.into_iter().map(|v| v.try_into()).collect()
    }
}

impl TryFrom<protowire::PruningPointsMessage> for PruningPointsList {
    type Error = ConversionError;
    fn try_from(msg: protowire::PruningPointsMessage) -> Result<Self, Self::Error> {
        msg.headers.into_iter().map(|x| x.try_into().map(Arc::new)).collect()
    }
}

impl TryFrom<protowire::TrustedDataMessage> for TrustedDataPackage {
    type Error = ConversionError;
    fn try_from(msg: protowire::TrustedDataMessage) -> Result<Self, Self::Error> {
        Ok(Self::new(
            msg.daa_window.into_iter().map(|x| x.try_into()).collect::<Result<Vec<_>, Self::Error>>()?,
            msg.ghostdag_data.into_iter().map(|x| x.try_into()).collect::<Result<Vec<_>, Self::Error>>()?,
        ))
    }
}

impl TryFrom<protowire::BlockWithTrustedDataV4Message> for TrustedDataEntry {
    type Error = ConversionError;
    fn try_from(msg: protowire::BlockWithTrustedDataV4Message) -> Result<Self, Self::Error> {
        Ok(Self::new(msg.block.try_into_ex()?, msg.daa_window_indices, msg.ghostdag_data_indices))
    }
}

impl TryFrom<protowire::IbdChainBlockLocatorMessage> for Vec<Hash> {
    type Error = ConversionError;
    fn try_from(msg: protowire::IbdChainBlockLocatorMessage) -> Result<Self, Self::Error> {
        msg.block_locator_hashes.into_iter().map(|v| v.try_into()).collect()
    }
}

impl TryFrom<protowire::BlockHeadersMessage> for Vec<Arc<Header>> {
    type Error = ConversionError;
    fn try_from(msg: protowire::BlockHeadersMessage) -> Result<Self, Self::Error> {
        msg.block_headers.into_iter().map(|v| v.try_into().map(Arc::new)).collect()
    }
}

impl TryFrom<protowire::PruningPointUtxoSetChunkMessage> for Vec<(TransactionOutpoint, UtxoEntry)> {
    type Error = ConversionError;

    fn try_from(msg: protowire::PruningPointUtxoSetChunkMessage) -> Result<Self, Self::Error> {
        msg.outpoint_and_utxo_entry_pairs.into_iter().map(|p| p.try_into()).collect()
    }
}

impl TryFrom<protowire::RequestPruningPointUtxoSetMessage> for Hash {
    type Error = ConversionError;

    fn try_from(msg: protowire::RequestPruningPointUtxoSetMessage) -> Result<Self, Self::Error> {
        msg.pruning_point_hash.try_into_ex()
    }
}

impl TryFrom<protowire::InvRelayBlockMessage> for Hash {
    type Error = ConversionError;

    fn try_from(msg: protowire::InvRelayBlockMessage) -> Result<Self, Self::Error> {
        msg.hash.try_into_ex()
    }
}

impl TryFrom<protowire::RequestRelayBlocksMessage> for Vec<Hash> {
    type Error = ConversionError;

    fn try_from(msg: protowire::RequestRelayBlocksMessage) -> Result<Self, Self::Error> {
        msg.hashes.into_iter().map(|v| v.try_into()).collect()
    }
}

impl TryFrom<protowire::RequestIbdBlocksMessage> for Vec<Hash> {
    type Error = ConversionError;

    fn try_from(msg: protowire::RequestIbdBlocksMessage) -> Result<Self, Self::Error> {
        msg.hashes.into_iter().map(|v| v.try_into()).collect()
    }
}

impl TryFrom<protowire::BlockLocatorMessage> for Vec<Hash> {
    type Error = ConversionError;

    fn try_from(msg: protowire::BlockLocatorMessage) -> Result<Self, Self::Error> {
        msg.hashes.into_iter().map(|v| v.try_into()).collect()
    }
}

impl TryFrom<protowire::AddressesMessage> for Vec<(IpAddress, u16)> {
    type Error = ConversionError;

    fn try_from(msg: protowire::AddressesMessage) -> Result<Self, Self::Error> {
        msg.address_list.into_iter().map(|addr| addr.try_into()).collect::<Result<_, _>>()
    }
}

impl TryFrom<protowire::RequestTransactionsMessage> for Vec<TransactionId> {
    type Error = ConversionError;

    fn try_from(msg: protowire::RequestTransactionsMessage) -> Result<Self, Self::Error> {
        msg.ids.into_iter().map(|v| v.try_into()).collect()
    }
}

impl TryFrom<protowire::InvTransactionsMessage> for Vec<TransactionId> {
    type Error = ConversionError;

    fn try_from(msg: protowire::InvTransactionsMessage) -> Result<Self, Self::Error> {
        msg.ids.into_iter().map(|v| v.try_into()).collect()
    }
}

impl TryFrom<protowire::TransactionNotFoundMessage> for TransactionId {
    type Error = ConversionError;

    fn try_from(msg: protowire::TransactionNotFoundMessage) -> Result<Self, Self::Error> {
        msg.id.try_into_ex()
    }
}

impl TryFrom<protowire::RequestBlockLocatorMessage> for (Hash, u32) {
    type Error = ConversionError;
    fn try_from(msg: protowire::RequestBlockLocatorMessage) -> Result<Self, Self::Error> {
        Ok((msg.high_hash.try_into_ex()?, msg.limit))
    }
}

impl TryFrom<protowire::RequestAntipastMessage> for (Hash, Hash) {
    type Error = ConversionError;
    fn try_from(msg: protowire::RequestAntipastMessage) -> Result<Self, Self::Error> {
        Ok((msg.block_hash.try_into_ex()?, msg.context_hash.try_into_ex()?))
    }
}
