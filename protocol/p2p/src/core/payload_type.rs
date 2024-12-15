use crate::pb::cryptixd_message::Payload as CryptixdMessagePayload;

#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, Hash, PartialEq)]
pub enum CryptixdMessagePayloadType {
    Addresses = 0,
    Block,
    Transaction,
    BlockLocator,
    RequestAddresses,
    RequestRelayBlocks,
    RequestTransactions,
    IbdBlock,
    InvRelayBlock,
    InvTransactions,
    Ping,
    Pong,
    Verack,
    Version,
    TransactionNotFound,
    Reject,
    PruningPointUtxoSetChunk,
    RequestIbdBlocks,
    UnexpectedPruningPoint,
    IbdBlockLocator,
    IbdBlockLocatorHighestHash,
    RequestNextPruningPointUtxoSetChunk,
    DonePruningPointUtxoSetChunks,
    IbdBlockLocatorHighestHashNotFound,
    BlockWithTrustedData,
    DoneBlocksWithTrustedData,
    RequestPruningPointAndItsAnticone,
    BlockHeaders,
    RequestNextHeaders,
    DoneHeaders,
    RequestPruningPointUtxoSet,
    RequestHeaders,
    RequestBlockLocator,
    PruningPoints,
    RequestPruningPointProof,
    PruningPointProof,
    Ready,
    BlockWithTrustedDataV4,
    TrustedData,
    RequestIbdChainBlockLocator,
    IbdChainBlockLocator,
    RequestAntipast,
    RequestNextPruningPointAndItsAnticoneBlocks,
}

impl From<&CryptixdMessagePayload> for CryptixdMessagePayloadType {
    fn from(payload: &CryptixdMessagePayload) -> Self {
        match payload {
            CryptixdMessagePayload::Addresses(_) => CryptixdMessagePayloadType::Addresses,
            CryptixdMessagePayload::Block(_) => CryptixdMessagePayloadType::Block,
            CryptixdMessagePayload::Transaction(_) => CryptixdMessagePayloadType::Transaction,
            CryptixdMessagePayload::BlockLocator(_) => CryptixdMessagePayloadType::BlockLocator,
            CryptixdMessagePayload::RequestAddresses(_) => CryptixdMessagePayloadType::RequestAddresses,
            CryptixdMessagePayload::RequestRelayBlocks(_) => CryptixdMessagePayloadType::RequestRelayBlocks,
            CryptixdMessagePayload::RequestTransactions(_) => CryptixdMessagePayloadType::RequestTransactions,
            CryptixdMessagePayload::IbdBlock(_) => CryptixdMessagePayloadType::IbdBlock,
            CryptixdMessagePayload::InvRelayBlock(_) => CryptixdMessagePayloadType::InvRelayBlock,
            CryptixdMessagePayload::InvTransactions(_) => CryptixdMessagePayloadType::InvTransactions,
            CryptixdMessagePayload::Ping(_) => CryptixdMessagePayloadType::Ping,
            CryptixdMessagePayload::Pong(_) => CryptixdMessagePayloadType::Pong,
            CryptixdMessagePayload::Verack(_) => CryptixdMessagePayloadType::Verack,
            CryptixdMessagePayload::Version(_) => CryptixdMessagePayloadType::Version,
            CryptixdMessagePayload::TransactionNotFound(_) => CryptixdMessagePayloadType::TransactionNotFound,
            CryptixdMessagePayload::Reject(_) => CryptixdMessagePayloadType::Reject,
            CryptixdMessagePayload::PruningPointUtxoSetChunk(_) => CryptixdMessagePayloadType::PruningPointUtxoSetChunk,
            CryptixdMessagePayload::RequestIbdBlocks(_) => CryptixdMessagePayloadType::RequestIbdBlocks,
            CryptixdMessagePayload::UnexpectedPruningPoint(_) => CryptixdMessagePayloadType::UnexpectedPruningPoint,
            CryptixdMessagePayload::IbdBlockLocator(_) => CryptixdMessagePayloadType::IbdBlockLocator,
            CryptixdMessagePayload::IbdBlockLocatorHighestHash(_) => CryptixdMessagePayloadType::IbdBlockLocatorHighestHash,
            CryptixdMessagePayload::RequestNextPruningPointUtxoSetChunk(_) => {
                CryptixdMessagePayloadType::RequestNextPruningPointUtxoSetChunk
            }
            CryptixdMessagePayload::DonePruningPointUtxoSetChunks(_) => CryptixdMessagePayloadType::DonePruningPointUtxoSetChunks,
            CryptixdMessagePayload::IbdBlockLocatorHighestHashNotFound(_) => {
                CryptixdMessagePayloadType::IbdBlockLocatorHighestHashNotFound
            }
            CryptixdMessagePayload::BlockWithTrustedData(_) => CryptixdMessagePayloadType::BlockWithTrustedData,
            CryptixdMessagePayload::DoneBlocksWithTrustedData(_) => CryptixdMessagePayloadType::DoneBlocksWithTrustedData,
            CryptixdMessagePayload::RequestPruningPointAndItsAnticone(_) => CryptixdMessagePayloadType::RequestPruningPointAndItsAnticone,
            CryptixdMessagePayload::BlockHeaders(_) => CryptixdMessagePayloadType::BlockHeaders,
            CryptixdMessagePayload::RequestNextHeaders(_) => CryptixdMessagePayloadType::RequestNextHeaders,
            CryptixdMessagePayload::DoneHeaders(_) => CryptixdMessagePayloadType::DoneHeaders,
            CryptixdMessagePayload::RequestPruningPointUtxoSet(_) => CryptixdMessagePayloadType::RequestPruningPointUtxoSet,
            CryptixdMessagePayload::RequestHeaders(_) => CryptixdMessagePayloadType::RequestHeaders,
            CryptixdMessagePayload::RequestBlockLocator(_) => CryptixdMessagePayloadType::RequestBlockLocator,
            CryptixdMessagePayload::PruningPoints(_) => CryptixdMessagePayloadType::PruningPoints,
            CryptixdMessagePayload::RequestPruningPointProof(_) => CryptixdMessagePayloadType::RequestPruningPointProof,
            CryptixdMessagePayload::PruningPointProof(_) => CryptixdMessagePayloadType::PruningPointProof,
            CryptixdMessagePayload::Ready(_) => CryptixdMessagePayloadType::Ready,
            CryptixdMessagePayload::BlockWithTrustedDataV4(_) => CryptixdMessagePayloadType::BlockWithTrustedDataV4,
            CryptixdMessagePayload::TrustedData(_) => CryptixdMessagePayloadType::TrustedData,
            CryptixdMessagePayload::RequestIbdChainBlockLocator(_) => CryptixdMessagePayloadType::RequestIbdChainBlockLocator,
            CryptixdMessagePayload::IbdChainBlockLocator(_) => CryptixdMessagePayloadType::IbdChainBlockLocator,
            CryptixdMessagePayload::RequestAntipast(_) => CryptixdMessagePayloadType::RequestAntipast,
            CryptixdMessagePayload::RequestNextPruningPointAndItsAnticoneBlocks(_) => {
                CryptixdMessagePayloadType::RequestNextPruningPointAndItsAnticoneBlocks
            }
        }
    }
}
